package yaraxwasm

import (
	"encoding/binary"
	"fmt"
	"io"
)

type scanResultDecoder struct {
	payload []byte
	offset  int
}

func (d *scanResultDecoder) readU32() (uint32, error) {
	if len(d.payload)-d.offset < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.LittleEndian.Uint32(d.payload[d.offset:])
	d.offset += 4
	return value, nil
}

func (d *scanResultDecoder) readU64() (uint64, error) {
	if len(d.payload)-d.offset < 8 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.LittleEndian.Uint64(d.payload[d.offset:])
	d.offset += 8
	return value, nil
}

func (d *scanResultDecoder) finish() error {
	if d.offset == len(d.payload) {
		return nil
	}
	return fmt.Errorf("scan result payload has %d trailing bytes", len(d.payload)-d.offset)
}

func decodeMatchingRulesBinary(payload []byte, staticRules []*Rule) ([]*Rule, error) {
	decoder := scanResultDecoder{payload: payload}

	rawCount, err := decoder.readU32()
	if err != nil {
		return nil, fmt.Errorf("read scan result rule count: %w", err)
	}
	ruleCount, err := intFromUint64(uint64(rawCount), "scan result rule count")
	if err != nil {
		return nil, err
	}

	ruleIndices := make([]uint32, ruleCount)
	totalPatternCount := 0
	totalMatchCount := 0

	for i := range ruleCount {
		ruleIndex, err := decoder.readU32()
		if err != nil {
			return nil, fmt.Errorf("read scan result rule index: %w", err)
		}
		if int(ruleIndex) >= len(staticRules) {
			return nil, fmt.Errorf(
				"scan result referenced rule index %d, but only %d static rules are available",
				ruleIndex,
				len(staticRules),
			)
		}

		baseRule := staticRules[ruleIndex]
		if baseRule == nil {
			return nil, fmt.Errorf("scan result referenced nil static rule at index %d", ruleIndex)
		}
		ruleIndices[i] = ruleIndex
		totalPatternCount += len(baseRule.patterns)

		for range baseRule.patterns {
			rawMatchCount, err := decoder.readU32()
			if err != nil {
				return nil, fmt.Errorf("read scan result match count: %w", err)
			}

			matchCount, err := intFromUint64(uint64(rawMatchCount), "scan result match count")
			if err != nil {
				return nil, err
			}
			totalMatchCount += matchCount

			byteCount := matchCount * 16
			if len(decoder.payload)-decoder.offset < byteCount {
				return nil, io.ErrUnexpectedEOF
			}
			decoder.offset += byteCount
		}
	}

	if err := decoder.finish(); err != nil {
		return nil, err
	}

	ruleValues := make([]Rule, ruleCount)
	matchingRules := make([]*Rule, ruleCount)

	var allPatterns []Pattern
	if totalPatternCount > 0 {
		allPatterns = make([]Pattern, totalPatternCount)
	}
	var allMatches []Match
	if totalMatchCount > 0 {
		allMatches = make([]Match, totalMatchCount)
	}

	decoder = scanResultDecoder{payload: payload}
	if _, err := decoder.readU32(); err != nil {
		return nil, fmt.Errorf("reread scan result rule count: %w", err)
	}

	patternOffset := 0
	matchOffset := 0
	for i, ruleIndex := range ruleIndices {
		if _, err := decoder.readU32(); err != nil {
			return nil, fmt.Errorf("reread scan result rule index: %w", err)
		}
		baseRule := staticRules[ruleIndex]
		patternCount := len(baseRule.patterns)
		rulePatterns := allPatterns[patternOffset : patternOffset+patternCount]

		for j, basePattern := range baseRule.patterns {
			rawMatchCount, err := decoder.readU32()
			if err != nil {
				return nil, fmt.Errorf("decode scan result match count: %w", err)
			}
			matchCount, err := intFromUint64(uint64(rawMatchCount), "scan result match count")
			if err != nil {
				return nil, err
			}

			ruleMatches := allMatches[matchOffset : matchOffset+matchCount]
			for k := range ruleMatches {
				offset, err := decoder.readU64()
				if err != nil {
					return nil, fmt.Errorf("decode scan result match offset: %w", err)
				}
				length, err := decoder.readU64()
				if err != nil {
					return nil, fmt.Errorf("decode scan result match length: %w", err)
				}
				ruleMatches[k] = Match{offset: offset, length: length}
			}
			rulePatterns[j] = Pattern{
				identifier: basePattern.identifier,
				matches:    ruleMatches,
			}
			matchOffset += matchCount
		}

		ruleValues[i] = Rule{
			namespace:  baseRule.namespace,
			identifier: baseRule.identifier,
			tags:       baseRule.tags,
			patterns:   rulePatterns,
			metadata:   baseRule.metadata,
		}
		matchingRules[i] = &ruleValues[i]
		patternOffset += patternCount
	}

	if err := decoder.finish(); err != nil {
		return nil, err
	}
	return matchingRules, nil
}
