package benchcmp

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cgobind "github.com/VirusTotal/yara-x/go"

	wasmbind "github.com/niallnsec/yaraxwasm"
)

const (
	yaraForgeRulesURL          = "https://github.com/YARAHQ/yara-forge/releases/download/20260322/yara-forge-rules-full.zip"
	yaraForgeRulesRelativePath = "packages/full/yara-rules-full.yar"
	wordpressCorpusURL         = "https://wordpress.org/latest.tar.gz"
)

type benchmarkFile struct {
	path string
	size int64
}

type externalBenchmarkData struct {
	yaraForgeRules      string
	yaraForgeRulesBytes int64
	wordpressFiles      []benchmarkFile
	wordpressBytes      int64
	wordpressMaxFile    int64
}

var (
	externalBenchmarkDataOnce sync.Once
	externalBenchmarkDataErr  error
	externalBenchmarkDataVal  externalBenchmarkData
)

func mustExternalBenchmarkData(tb testing.TB) externalBenchmarkData {
	tb.Helper()
	externalBenchmarkDataOnce.Do(func() {
		externalBenchmarkDataVal, externalBenchmarkDataErr = loadExternalBenchmarkData()
	})
	if externalBenchmarkDataErr != nil {
		tb.Fatalf("load benchmark datasets: %v", externalBenchmarkDataErr)
	}
	return externalBenchmarkDataVal
}

func loadExternalBenchmarkData() (externalBenchmarkData, error) {
	cacheDir, err := benchmarkDataDir()
	if err != nil {
		return externalBenchmarkData{}, err
	}

	rulesArchivePath := filepath.Join(cacheDir, "yara-forge-rules-full-20260322.zip")
	if _, err := downloadFile(yaraForgeRulesURL, rulesArchivePath, false); err != nil {
		return externalBenchmarkData{}, err
	}

	rulesExtractDir := filepath.Join(cacheDir, "yara-forge-rules-full-20260322")
	rulesSourcePath := filepath.Join(rulesExtractDir, filepath.FromSlash(yaraForgeRulesRelativePath))
	if _, err := os.Stat(rulesSourcePath); errors.Is(err, os.ErrNotExist) {
		if err := extractZipArchive(rulesArchivePath, rulesExtractDir); err != nil {
			return externalBenchmarkData{}, err
		}
	} else if err != nil {
		return externalBenchmarkData{}, err
	}

	rulesSource, err := os.ReadFile(rulesSourcePath)
	if err != nil {
		return externalBenchmarkData{}, err
	}

	wordpressArchivePath := filepath.Join(cacheDir, "wordpress-latest.tar.gz")
	wordpressArchiveUpdated, err := downloadFile(wordpressCorpusURL, wordpressArchivePath, true)
	if err != nil {
		return externalBenchmarkData{}, err
	}

	wordpressExtractDir := filepath.Join(cacheDir, "wordpress-latest")
	wordpressRoot := filepath.Join(wordpressExtractDir, "wordpress")
	wordpressSentinel := filepath.Join(wordpressRoot, "index.php")
	if _, err := os.Stat(wordpressSentinel); errors.Is(err, os.ErrNotExist) || wordpressArchiveUpdated {
		if err := extractTarGzArchive(wordpressArchivePath, wordpressExtractDir); err != nil {
			return externalBenchmarkData{}, err
		}
	} else if err != nil {
		return externalBenchmarkData{}, err
	}

	wordpressFiles, wordpressBytes, err := collectRegularFiles(wordpressRoot)
	if err != nil {
		return externalBenchmarkData{}, err
	}

	return externalBenchmarkData{
		yaraForgeRules:      string(rulesSource),
		yaraForgeRulesBytes: int64(len(rulesSource)),
		wordpressFiles:      wordpressFiles,
		wordpressBytes:      wordpressBytes,
		wordpressMaxFile:    maxFileSize(wordpressFiles),
	}, nil
}

func benchmarkDataDir() (string, error) {
	if root := os.Getenv("COMPARE_BENCH_DATA_DIR"); root != "" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return "", err
		}
		return root, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	root := filepath.Join(wd, ".tmp", "datasets")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	return root, nil
}

func downloadFile(url string, destination string, refresh bool) (bool, error) {
	if !refresh {
		if info, err := os.Stat(destination); err == nil && info.Size() > 0 {
			return false, nil
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return false, err
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(destination), ".download-*")
	if err != nil {
		return false, err
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "yaraxwasm-benchcmp")

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("download %s: unexpected status %s", url, resp.Status)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return false, err
	}
	if err := tmpFile.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpFile.Name(), destination); err != nil {
		return false, err
	}
	return true, nil
}

func extractZipArchive(archivePath string, destination string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	return replaceDir(destination, func(root string) error {
		for _, file := range reader.File {
			targetPath, err := extractionPath(root, file.Name)
			if err != nil {
				return err
			}

			mode := file.Mode()
			if file.FileInfo().IsDir() {
				if err := os.MkdirAll(targetPath, mode.Perm()); err != nil {
					return err
				}
				continue
			}

			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}

			src, err := file.Open()
			if err != nil {
				return err
			}

			dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
			if err != nil {
				src.Close()
				return err
			}

			_, copyErr := io.Copy(dst, src)
			closeErr := dst.Close()
			srcErr := src.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if srcErr != nil {
				return srcErr
			}
		}
		return nil
	})
}

func extractTarGzArchive(archivePath string, destination string) error {
	return replaceDir(destination, func(root string) error {
		archiveFile, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer archiveFile.Close()

		gzipReader, err := gzip.NewReader(archiveFile)
		if err != nil {
			return err
		}
		defer gzipReader.Close()

		tarReader := tar.NewReader(gzipReader)
		for {
			header, err := tarReader.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}

			targetPath, err := extractionPath(root, header.Name)
			if err != nil {
				return err
			}

			switch header.Typeflag {
			case tar.TypeDir:
				if err := os.MkdirAll(targetPath, fs.FileMode(header.Mode).Perm()); err != nil {
					return err
				}
			case tar.TypeReg, 0:
				if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
					return err
				}
				dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(header.Mode).Perm())
				if err != nil {
					return err
				}
				_, copyErr := io.Copy(dst, tarReader)
				closeErr := dst.Close()
				if copyErr != nil {
					return copyErr
				}
				if closeErr != nil {
					return closeErr
				}
			default:
				continue
			}
		}
	})
}

func replaceDir(destination string, populate func(root string) error) error {
	tmpDir := destination + ".extracting"
	if err := os.RemoveAll(tmpDir); err != nil {
		return err
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	if err := populate(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}
	if err := os.RemoveAll(destination); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}
	return os.Rename(tmpDir, destination)
}

func extractionPath(root string, name string) (string, error) {
	cleanName := filepath.Clean(filepath.FromSlash(name))
	if cleanName == "." {
		return root, nil
	}

	targetPath := filepath.Join(root, cleanName)
	rel, err := filepath.Rel(root, targetPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return targetPath, nil
}

func collectRegularFiles(root string) ([]benchmarkFile, int64, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, 0, err
	}
	if !info.IsDir() {
		return nil, 0, fmt.Errorf("benchmark corpus root is not a directory: %s", root)
	}

	files := make([]benchmarkFile, 0)
	var totalBytes int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		files = append(files, benchmarkFile{
			path: path,
			size: info.Size(),
		})
		totalBytes += info.Size()
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].path < files[j].path
	})

	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no files found under %s", root)
	}
	return files, totalBytes, nil
}

func maxFileSize(files []benchmarkFile) int64 {
	var maxSize int64
	for _, file := range files {
		if file.size > maxSize {
			maxSize = file.size
		}
	}
	return maxSize
}

func mustInt64ToInt(tb testing.TB, value int64, what string) int {
	tb.Helper()
	if value < 0 {
		tb.Fatalf("invalid %s: %d", what, value)
	}
	maxInt := int64(^uint(0) >> 1)
	if value > maxInt {
		tb.Fatalf("%s %d exceeds host int capacity", what, value)
	}
	return int(value)
}

func makeReusableScanBuffer(tb testing.TB, capacity int64) []byte {
	tb.Helper()
	return make([]byte, 0, mustInt64ToInt(tb, capacity, "scan buffer capacity"))
}

func readFileIntoBuffer(path string, buf []byte) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("benchmark corpus entry is not a regular file: %s", path)
	}
	if info.Size() < 0 {
		return nil, fmt.Errorf("benchmark corpus entry has negative size: %s", path)
	}
	maxInt := int64(^uint(0) >> 1)
	if info.Size() > maxInt {
		return nil, fmt.Errorf("benchmark corpus entry exceeds host int capacity: %s", path)
	}

	size := int(info.Size())
	buf = slices.Grow(buf[:0], size)[:size]
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return buf, nil
}

func mustCGOYaraForgeRules(tb testing.TB, data externalBenchmarkData) *cgobind.Rules {
	tb.Helper()
	rules, err := cgobind.Compile(data.yaraForgeRules)
	if err != nil {
		tb.Fatalf("compile cgo YARA Forge rules: %v", err)
	}
	return rules
}

func mustWASMYaraForgeRules(tb testing.TB, data externalBenchmarkData) *wasmbind.Rules {
	tb.Helper()
	ensureWASMInitialised(tb)
	rules, err := wasmbind.Compile(data.yaraForgeRules)
	if err != nil {
		tb.Fatalf("compile wasm YARA Forge rules: %v", err)
	}
	return rules
}

func mustWASMMmapYaraForgeRules(tb testing.TB, data externalBenchmarkData) *wasmbind.Rules {
	tb.Helper()
	ensureWASMMmapInitialised(tb)
	rules, err := wasmbind.Compile(data.yaraForgeRules)
	if err != nil {
		tb.Fatalf("compile wasm YARA Forge rules with mmap allocator: %v", err)
	}
	return rules
}

func consumeCGOMatchCounts(tb testing.TB, results *cgobind.ScanResults, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("scan failed: %v", err)
	}
	benchmarkSink += uint64(len(results.MatchingRules()))
}

func consumeWASMMatchCounts(tb testing.TB, results *wasmbind.ScanResults, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("scan failed: %v", err)
	}
	benchmarkSink += uint64(len(results.MatchingRules()))
}

func BenchmarkCGOLoadRuleset(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	warmRules := mustCGOYaraForgeRules(b, data)
	warmRules.Destroy()
	b.SetBytes(data.yaraForgeRulesBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		rules := mustCGOYaraForgeRules(b, data)
		rules.Destroy()
	}
}

func BenchmarkWASMLoadRuleset(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	warmRules := mustWASMYaraForgeRules(b, data)
	warmRules.Destroy()
	b.SetBytes(data.yaraForgeRulesBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		rules := mustWASMYaraForgeRules(b, data)
		rules.Destroy()
	}
}

func BenchmarkCGOScanWordPressCorpus(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	rules := mustCGOYaraForgeRules(b, data)
	defer rules.Destroy()

	scanner := cgobind.NewScanner(rules)
	defer scanner.Destroy()

	results, err := scanner.ScanFile(data.wordpressFiles[0].path)
	consumeCGOMatchCounts(b, results, err)
	b.SetBytes(data.wordpressBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		for _, file := range data.wordpressFiles {
			results, err := scanner.ScanFile(file.path)
			consumeCGOMatchCounts(b, results, err)
		}
	}
}

func BenchmarkWASMScanWordPressCorpus(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	rules := mustWASMYaraForgeRules(b, data)
	defer rules.Destroy()

	scanner := wasmbind.NewScanner(rules)
	defer scanner.Destroy()

	results, err := scanner.ScanFile(data.wordpressFiles[0].path)
	consumeWASMMatchCounts(b, results, err)
	b.SetBytes(data.wordpressBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		for _, file := range data.wordpressFiles {
			results, err := scanner.ScanFile(file.path)
			consumeWASMMatchCounts(b, results, err)
		}
	}
}

func BenchmarkCGOScanWordPressCorpusBuffered(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	rules := mustCGOYaraForgeRules(b, data)
	defer rules.Destroy()

	scanner := cgobind.NewScanner(rules)
	defer scanner.Destroy()

	scanBuf := makeReusableScanBuffer(b, data.wordpressMaxFile)
	scanBuf, err := readFileIntoBuffer(data.wordpressFiles[0].path, scanBuf)
	if err != nil {
		b.Fatalf("read warmup file: %v", err)
	}
	results, err := scanner.Scan(scanBuf)
	consumeCGOMatchCounts(b, results, err)
	b.SetBytes(data.wordpressBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		for _, file := range data.wordpressFiles {
			scanBuf, err = readFileIntoBuffer(file.path, scanBuf)
			if err != nil {
				b.Fatalf("read %s: %v", file.path, err)
			}
			results, err := scanner.Scan(scanBuf)
			consumeCGOMatchCounts(b, results, err)
		}
	}
}

func BenchmarkWASMScanWordPressCorpusBuffered(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	rules := mustWASMYaraForgeRules(b, data)
	defer rules.Destroy()

	scanner := wasmbind.NewScanner(rules)
	defer scanner.Destroy()

	scanBuf := makeReusableScanBuffer(b, data.wordpressMaxFile)
	scanBuf, err := readFileIntoBuffer(data.wordpressFiles[0].path, scanBuf)
	if err != nil {
		b.Fatalf("read warmup file: %v", err)
	}
	results, err := scanner.Scan(scanBuf)
	consumeWASMMatchCounts(b, results, err)
	b.SetBytes(data.wordpressBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		for _, file := range data.wordpressFiles {
			scanBuf, err = readFileIntoBuffer(file.path, scanBuf)
			if err != nil {
				b.Fatalf("read %s: %v", file.path, err)
			}
			results, err := scanner.Scan(scanBuf)
			consumeWASMMatchCounts(b, results, err)
		}
	}
}

func BenchmarkWASMScanWordPressCorpusMmap(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	rules := mustWASMMmapYaraForgeRules(b, data)
	defer rules.Destroy()

	scanner := wasmbind.NewScanner(rules)
	defer scanner.Destroy()

	results, err := scanner.ScanFile(data.wordpressFiles[0].path)
	consumeWASMMatchCounts(b, results, err)
	b.SetBytes(data.wordpressBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		for _, file := range data.wordpressFiles {
			results, err := scanner.ScanFile(file.path)
			consumeWASMMatchCounts(b, results, err)
		}
	}
}

func BenchmarkWASMScanWordPressCorpusBufferedMmap(b *testing.B) {
	b.ReportAllocs()
	data := mustExternalBenchmarkData(b)

	b.StopTimer()
	rules := mustWASMMmapYaraForgeRules(b, data)
	defer rules.Destroy()

	scanner := wasmbind.NewScanner(rules)
	defer scanner.Destroy()

	scanBuf := makeReusableScanBuffer(b, data.wordpressMaxFile)
	scanBuf, err := readFileIntoBuffer(data.wordpressFiles[0].path, scanBuf)
	if err != nil {
		b.Fatalf("read warmup file: %v", err)
	}
	results, err := scanner.Scan(scanBuf)
	consumeWASMMatchCounts(b, results, err)
	b.SetBytes(data.wordpressBytes)
	b.ResetTimer()
	b.StartTimer()

	for range b.N {
		for _, file := range data.wordpressFiles {
			scanBuf, err = readFileIntoBuffer(file.path, scanBuf)
			if err != nil {
				b.Fatalf("read %s: %v", file.path, err)
			}
			results, err := scanner.Scan(scanBuf)
			consumeWASMMatchCounts(b, results, err)
		}
	}
}
