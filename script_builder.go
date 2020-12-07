package bytes

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	OP_0         = 0x00 // 0
	OP_DATA_1    = 0x01 // 1
	OP_PUSHDATA1 = 0x4c // 76
	OP_PUSHDATA2 = 0x4d // 77
	OP_PUSHDATA4 = 0x4e // 78
	OP_1NEGATE   = 0x4f // 79
	OP_1         = 0x51 // 81 - AKA OP_TRUE
	// defaultScriptAlloc is the default size used for the backing array
	// for a script being built by the ScriptBuilder.  The array will
	// dynamically grow as needed, but this figure is intended to provide
	// enough space for vast majority of scripts without needing to grow the
	// backing array multiple times.
	defaultScriptAlloc = 500
)

type ScriptBuilder struct {
	script []byte
	err    error
}

// AddOp pushes the passed opcode to the end of the script.  The script will not
// be modified if pushing the opcode would cause the script to exceed the
// maximum allowed script engine size.
func (b *ScriptBuilder) AddOp(opcode byte) *ScriptBuilder {
	if b.err != nil {
		return b
	}

	// Pushes that would cause the script to exceed the largest allowed
	// script size would result in a non-canonical script.
	if len(b.script)+1 > 10000 {
		str := fmt.Sprintf("adding an opcode would exceed the maximum "+
			"allowed canonical script length of %d", 10000)
		b.err = errors.New(str)
		return b
	}

	b.script = append(b.script, opcode)
	return b
}

// AddOps pushes the passed opcodes to the end of the script.  The script will
// not be modified if pushing the opcodes would cause the script to exceed the
// maximum allowed script engine size.
func (b *ScriptBuilder) AddOps(opcodes []byte) *ScriptBuilder {
	if b.err != nil {
		return b
	}

	// Pushes that would cause the script to exceed the largest allowed
	// script size would result in a non-canonical script.
	if len(b.script)+len(opcodes) > 10000 {
		str := fmt.Sprintf("adding opcodes would exceed the maximum "+
			"allowed canonical script length of %d", 10000)
		b.err = errors.New(str)
		return b
	}

	b.script = append(b.script, opcodes...)
	return b
}

// canonicalDataSize returns the number of bytes the canonical encoding of the
// data will take.
func canonicalDataSize(data []byte) int {
	dataLen := len(data)

	// When the data consists of a single number that can be represented
	// by one of the "small integer" opcodes, that opcode will be instead
	// of a data push opcode followed by the number.
	if dataLen == 0 {
		return 1
	} else if dataLen == 1 && data[0] <= 16 {
		return 1
	} else if dataLen == 1 && data[0] == 0x81 {
		return 1
	}

	if dataLen < OP_PUSHDATA1 {
		return 1 + dataLen
	} else if dataLen <= 0xff {
		return 2 + dataLen
	} else if dataLen <= 0xffff {
		return 3 + dataLen
	}

	return 5 + dataLen
}

// addData is the internal function that actually pushes the passed data to the
// end of the script.  It automatically chooses canonical opcodes depending on
// the length of the data.  A zero length buffer will lead to a push of empty
// data onto the stack (OP_0).  No data limits are enforced with this function.
func (b *ScriptBuilder) addData(data []byte) *ScriptBuilder {
	dataLen := len(data)

	// When the data consists of a single number that can be represented
	// by one of the "small integer" opcodes, use that opcode instead of
	// a data push opcode followed by the number.
	if dataLen == 0 || dataLen == 1 && data[0] == 0 {
		b.script = append(b.script, OP_0)
		return b
	} else if dataLen == 1 && data[0] <= 16 {
		b.script = append(b.script, (OP_1-1)+data[0])
		return b
	} else if dataLen == 1 && data[0] == 0x81 {
		b.script = append(b.script, byte(OP_1NEGATE))
		return b
	}

	// Use one of the OP_DATA_# opcodes if the length of the data is small
	// enough so the data push instruction is only a single byte.
	// Otherwise, choose the smallest possible OP_PUSHDATA# opcode that
	// can represent the length of the data.
	if dataLen < OP_PUSHDATA1 {
		b.script = append(b.script, byte((OP_DATA_1-1)+dataLen))
	} else if dataLen <= 0xff {
		b.script = append(b.script, OP_PUSHDATA1, byte(dataLen))
	} else if dataLen <= 0xffff {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(dataLen))
		b.script = append(b.script, OP_PUSHDATA2)
		b.script = append(b.script, buf...)
	} else {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(dataLen))
		b.script = append(b.script, OP_PUSHDATA4)
		b.script = append(b.script, buf...)
	}

	// Append the actual data.
	b.script = append(b.script, data...)

	return b
}

// AddFullData should not typically be used by ordinary users as it does not
// include the checks which prevent data pushes larger than the maximum allowed
// sizes which leads to scripts that can't be executed.  This is provided for
// testing purposes such as regression tests where sizes are intentionally made
// larger than allowed.
//
// Use AddData instead.
func (b *ScriptBuilder) AddFullData(data []byte) *ScriptBuilder {
	if b.err != nil {
		return b
	}

	return b.addData(data)
}

// AddData pushes the passed data to the end of the script.  It automatically
// chooses canonical opcodes depending on the length of the data.  A zero length
// buffer will lead to a push of empty data onto the stack (OP_0) and any push
// of data greater than MaxScriptElementSize will not modify the script since
// that is not allowed by the script engine.  Also, the script will not be
// modified if pushing the data would cause the script to exceed the maximum
// allowed script engine size.
func (b *ScriptBuilder) AddData(data []byte) *ScriptBuilder {
	if b.err != nil {
		return b
	}

	// Pushes that would cause the script to exceed the largest allowed
	// script size would result in a non-canonical script.
	dataSize := canonicalDataSize(data)
	if len(b.script)+dataSize > 10000 {
		str := fmt.Sprintf("adding %d bytes of data would exceed the "+
			"maximum allowed canonical script length of %d",
			dataSize, 10000)
		b.err = errors.New(str)
		return b
	}

	// Pushes larger than the max script element size would result in a
	// script that is not canonical.
	dataLen := len(data)
	if dataLen > 10000 {
		str := fmt.Sprintf("adding a data element of %d bytes would "+
			"exceed the maximum allowed script element size of %d",
			dataLen, 10000)
		b.err = errors.New(str)
		return b
	}

	return b.addData(data)
}

// AddInt64 pushes the passed integer to the end of the script.  The script will
// not be modified if pushing the data would cause the script to exceed the
// maximum allowed script engine size.
func (b *ScriptBuilder) AddInt64(val int64) *ScriptBuilder {
	if b.err != nil {
		return b
	}

	// Pushes that would cause the script to exceed the largest allowed
	// script size would result in a non-canonical script.
	if len(b.script)+1 > 10000 {
		str := fmt.Sprintf("adding an integer would exceed the "+
			"maximum allow canonical script length of %d",
			10000)
		b.err = errors.New(str)
		return b
	}

	// Fast path for small integers and OP_1NEGATE.
	if val == 0 {
		b.script = append(b.script, OP_0)
		return b
	}
	if val == -1 || (val >= 1 && val <= 16) {
		b.script = append(b.script, byte((OP_1-1)+val))
		return b
	}

	return b.AddData(scriptNum(val).Bytes())
}

// Reset resets the script so it has no content.
func (b *ScriptBuilder) Reset() *ScriptBuilder {
	b.script = b.script[0:0]
	b.err = nil
	return b
}

// Script returns the currently built script.  When any errors occurred while
// building the script, the script will be returned up the point of the first
// error along with the error.
func (b *ScriptBuilder) Script() ([]byte, error) {
	return b.script, b.err
}

// NewScriptBuilder returns a new instance of a script builder.  See
// ScriptBuilder for details.
func NewScriptBuilder() *ScriptBuilder {
	return &ScriptBuilder{
		script: make([]byte, 0, defaultScriptAlloc),
	}
}
