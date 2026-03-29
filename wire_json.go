package yaraxwasm

//easyjson:json
//nolint:recvcheck // easyjson generates pointer receivers for unmarshal and value receivers for marshal.
type ruleJSONList []ruleJSON

//easyjson:json
//nolint:recvcheck // easyjson generates pointer receivers for unmarshal and value receivers for marshal.
type profilingInfoJSONList []profilingInfoJSON

//easyjson:json
//nolint:recvcheck // easyjson generates pointer receivers for unmarshal and value receivers for marshal.
type compileErrorList []CompileError

//easyjson:json
//nolint:recvcheck // easyjson generates pointer receivers for unmarshal and value receivers for marshal.
type warningList []Warning
