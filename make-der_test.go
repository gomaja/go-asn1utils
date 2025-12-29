package asn1utils

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMakeDER(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "DER already that must provide the same bytes output",
			input:   "6259480403ed2d126b1a2818060700118605010101a00d600ba1090607040000010005036c35a1330201c5020116302b80049152828883010086079152629610103287050583370000aa0a0a0104040504038090a3ab04030205e0",
			want:    "6259480403ed2d126b1a2818060700118605010101a00d600ba1090607040000010005036c35a1330201c5020116302b80049152828883010086079152629610103287050583370000aa0a0a0104040504038090a3ab04030205e0",
			wantErr: false,
		},
		{
			name:    "invoke sendRoutingInfoForSM (ShortMsgGatewayContext) [Boolean Type included]",
			input:   "3019800a915282051447720982f9810101820891328490001015f8",
			want:    "3019800a915282051447720982f98101ff820891328490001015f8",
			wantErr: false,
		},
		{
			name:    "returnError (ShortMsgMTRelayContext)",
			input:   "6443490400519a286b2a2828060700118605010101a01d611b80020780a109060704000001001903a203020100a305a1030201006c80a30b02010002010630030201010000",
			want:    "6441490400519a286b2a2828060700118605010101a01d611b80020780a109060704000001001903a203020100a305a1030201006c0da30b0201000201063003020101",
			wantErr: false,
		},
		{
			name:    "returnResultLast mt-forwardSM (ShortMsgMTRelayContext)",
			input:   "6443490400519a286b2a2828060700118605010101a01d611b80020780a109060704000001001903a203020100a305a1030201006c80a30b02010002010630030201010000",
			want:    "6441490400519a286b2a2828060700118605010101a01d611b80020780a109060704000001001903a203020100a305a1030201006c0da30b0201000201063003020101",
			wantErr: false,
		},
		{
			name:    "Camel-V2 invoke initialDP (CapGsmssfToGsmscfContext)",
			input:   "6281a94804b70801a16b1e281c060700118605010101a011600f80020780a1090607040000010032016c80a17d020100020100307580010183070313890027821785010a8a088493975617699909bb0580038090a39c01029f320852507017322911f7bf34170201008107919756176999f9a309800752f099d05b37d0bf35038301119f3605f943d000039f3707919756176999f99f3807819830535304f99f390802420122806080020000",
			want:    "6281a74804b70801a16b1e281c060700118605010101a011600f80020780a1090607040000010032016c7fa17d020100020100307580010183070313890027821785010a8a088493975617699909bb0580038090a39c01029f320852507017322911f7bf34170201008107919756176999f9a309800752f099d05b37d0bf35038301119f3605f943d000039f3707919756176999f99f3807819830535304f99f39080242012280608002",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Decode hex string to bytes
			originalBytes, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}

			got, err := MakeDER(originalBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeDER() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			wantBytes, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("Failed to decode expected hex string: %v", err)
			}

			if !bytes.Equal(got, wantBytes) {
				t.Errorf("MakeDER() = %x, want %x", got, wantBytes)
			}

		})
	}
}

func TestMakeDER_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty input",
			input: []byte{},
		},
		{
			name:  "extra data after structure",
			input: []byte{0x02, 0x01, 0x05, 0xFF}, // INTEGER 5, then extra 0xFF
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MakeDER(tt.input)
			if err == nil {
				t.Errorf("MakeDER() expected error, got nil")
			}
		})
	}
}

func TestParseElement_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "truncated tag bytes in long form",
			input: "1f", // long-form tag, but no subsequent bytes
		},
		{
			name:  "tag number too large",
			input: "1f8080808080808080", // excessively long tag
		},
		{
			name:  "unexpected end after tag",
			input: "02", // INTEGER tag, no length byte
		},
		{
			name:  "length bytes exceed data",
			input: "0282ffff", // claims 65535 bytes length, but no data
		},
		{
			name:  "indefinite length on primitive",
			input: "0480", // OCTET STRING primitive with indefinite length (invalid)
		},
		{
			name:  "definite length exceeds data",
			input: "0405aabbcc", // claims 5 bytes, only 3 provided
		},
		{
			name:  "constructed length mismatch",
			input: "3005020101020102", // SEQUENCE claims 5 bytes, but content is 6
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			_, err := MakeDER(input)
			if err == nil {
				t.Errorf("MakeDER() expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestLongFormTag(t *testing.T) {
	// Test long-form tag encoding (tag number >= 31)
	// Tag class 2 (context-specific), constructed, tag number 31
	// 0xBF = 10111111 (class 2, constructed, 0x1F indicating long form)
	// 0x1F = 00011111 (tag number 31, MSB=0 means last byte)
	input := []byte{0xBF, 0x1F, 0x03, 0x02, 0x01, 0x05} // [31] CONSTRUCTED { INTEGER 5 }
	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("MakeDER() = %x, want %x", got, input)
	}
}

func TestLongFormTagMultipleOctets(t *testing.T) {
	// Tag number 200 (needs 2 bytes in long form: 0x81, 0x48)
	// 200 = 0xC8 = 11001000 in binary
	// In base-128: 200 / 128 = 1 remainder 72
	// So: 0x81 (1 with continuation), 0x48 (72, no continuation)
	input := []byte{0xBF, 0x81, 0x48, 0x03, 0x02, 0x01, 0x05} // [200] CONSTRUCTED { INTEGER 5 }
	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("MakeDER() = %x, want %x", got, input)
	}
}

func TestLongFormLength(t *testing.T) {
	// Create a large enough content to require long-form length encoding
	// Length 200 bytes requires: 0x81 0xC8 (1 length byte, value 200)
	content := make([]byte, 200)
	for i := range content {
		content[i] = byte(i % 256)
	}
	input := append([]byte{0x04, 0x81, 0xC8}, content...) // OCTET STRING with 200 bytes

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("MakeDER() length mismatch: got %d bytes, want %d bytes", len(got), len(input))
	}
}

func TestLongFormLengthTwoBytes(t *testing.T) {
	// Length 300 bytes requires: 0x82 0x01 0x2C (2 length bytes, value 300)
	content := make([]byte, 300)
	for i := range content {
		content[i] = byte(i % 256)
	}
	input := append([]byte{0x04, 0x82, 0x01, 0x2C}, content...) // OCTET STRING with 300 bytes

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("MakeDER() length mismatch: got %d bytes, want %d bytes", len(got), len(input))
	}
}

func TestBooleanNormalization(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "boolean true (non-0xFF)",
			input: "010101", // BOOLEAN TRUE (value 0x01)
			want:  "0101ff", // normalized to 0xFF
		},
		{
			name:  "boolean true (0x42)",
			input: "010142", // BOOLEAN TRUE (value 0x42)
			want:  "0101ff", // normalized to 0xFF
		},
		{
			name:  "boolean false",
			input: "010100", // BOOLEAN FALSE
			want:  "010100", // stays 0x00
		},
		{
			name:  "context-specific boolean true",
			input: "810105", // [1] IMPLICIT BOOLEAN TRUE
			want:  "8101ff", // normalized to 0xFF
		},
		{
			name:  "context-specific boolean false",
			input: "810100", // [1] IMPLICIT BOOLEAN FALSE
			want:  "810100", // stays 0x00
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			want, _ := hex.DecodeString(tt.want)

			got, err := MakeDER(input)
			if err != nil {
				t.Fatalf("MakeDER() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MakeDER() = %x, want %x", got, want)
			}
		})
	}
}

func TestConstructedBitStringFlattening(t *testing.T) {
	// Constructed BIT STRING with two primitive chunks
	// First chunk: unused bits = 0, data = 0xAB
	// Second chunk: unused bits = 4, data = 0xCD
	// 23 80 (BIT STRING constructed indefinite)
	//   03 02 00 AB (BIT STRING primitive, 0 unused bits, data AB)
	//   03 02 04 CD (BIT STRING primitive, 4 unused bits, data CD)
	// 00 00 (EOC)
	input, _ := hex.DecodeString("2380030200ab030204cd0000")
	// Expected flattened: 03 04 04 AB CD (BIT STRING primitive, 4 unused bits, data AB CD)
	want, _ := hex.DecodeString("030304abcd")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestConstructedOctetStringFlattening(t *testing.T) {
	// Constructed OCTET STRING with two primitive chunks
	// 24 80 (OCTET STRING constructed indefinite)
	//   04 02 AB CD (OCTET STRING primitive)
	//   04 02 EF 01 (OCTET STRING primitive)
	// 00 00 (EOC)
	input, _ := hex.DecodeString("24800402abcd0402ef010000")
	// Expected flattened: 04 04 AB CD EF 01
	want, _ := hex.DecodeString("0404abcdef01")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestConstructedUTF8StringFlattening(t *testing.T) {
	// Constructed UTF8String (tag 12 = 0x0C) with two primitive chunks
	// 2C 80 (UTF8String constructed indefinite)
	//   0C 02 48 69 (UTF8String primitive "Hi")
	//   0C 01 21 (UTF8String primitive "!")
	// 00 00 (EOC)
	input, _ := hex.DecodeString("2c800c0248690c01210000")
	// Expected flattened: 0C 03 48 69 21 ("Hi!")
	want, _ := hex.DecodeString("0c03486921")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestConstructedPrintableStringFlattening(t *testing.T) {
	// Constructed PrintableString (tag 19 = 0x13) with two primitive chunks
	// 33 80 (PrintableString constructed indefinite)
	//   13 02 41 42 (PrintableString primitive "AB")
	//   13 02 43 44 (PrintableString primitive "CD")
	// 00 00 (EOC)
	input, _ := hex.DecodeString("338013024142130243440000")
	// Expected flattened: 13 04 41 42 43 44 ("ABCD")
	want, _ := hex.DecodeString("130441424344")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestConstructedIA5StringFlattening(t *testing.T) {
	// Constructed IA5String (tag 22 = 0x16)
	// 36 80 (IA5String constructed, indefinite length)
	//   16 02 41 42 (IA5String primitive "AB")
	//   16 02 43 44 (IA5String primitive "CD")
	// 00 00 (EOC)
	input, _ := hex.DecodeString("368016024142160243440000")
	// Expected flattened: 16 04 41 42 43 44 ("ABCD")
	want, _ := hex.DecodeString("160441424344")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestSetSorting(t *testing.T) {
	// SET containing elements in non-DER order
	// SET { INTEGER 5, BOOLEAN TRUE, INTEGER 1 }
	// Should be sorted by encoded bytes
	// 31 09 (SET, length 9)
	//   02 01 05 (INTEGER 5)
	//   01 01 FF (BOOLEAN TRUE)
	//   02 01 01 (INTEGER 1)
	input, _ := hex.DecodeString("3109020105010101020101")
	// After sorting: BOOLEAN TRUE (0101FF), INTEGER 1 (020101), INTEGER 5 (020105)
	// Note: 0101FF < 020101 < 020105 lexicographically
	want, _ := hex.DecodeString("31090101ff020101020105")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestSetOfSorting(t *testing.T) {
	// SET OF INTEGER with elements in non-sorted order
	// SET { INTEGER 10, INTEGER 5, INTEGER 1 }
	input, _ := hex.DecodeString("3109020101020105020100")
	// After sorting: 020100, 020101, 020105
	want, _ := hex.DecodeString("3109020100020101020105")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestBitStringErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "BIT STRING with invalid sub-element type",
			input: "23800201050000", // constructed BIT STRING containing INTEGER
		},
		{
			name:  "BIT STRING with empty sub-element",
			input: "238003000000", // constructed BIT STRING with empty primitive BIT STRING
		},
		{
			name:  "BIT STRING intermediate chunk with non-zero unused bits",
			input: "2380030201ab030204cd0000", // first chunk has unused bits = 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			_, err := MakeDER(input)
			if err == nil {
				t.Errorf("MakeDER() expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestOctetStringErrorCases(t *testing.T) {
	// Constructed OCTET STRING with invalid sub-element (INTEGER instead of OCTET STRING)
	input, _ := hex.DecodeString("24800201050000")
	_, err := MakeDER(input)
	if err == nil {
		t.Errorf("MakeDER() expected error for OCTET STRING with invalid sub-element")
	}
}

func TestStringTypesErrorCases(t *testing.T) {
	// Constructed UTF8String with invalid sub-element (INTEGER instead of UTF8String)
	input, _ := hex.DecodeString("2c800201050000")
	_, err := MakeDER(input)
	if err == nil {
		t.Errorf("MakeDER() expected error for UTF8String with invalid sub-element")
	}
}

func TestIndefiniteLengthSequence(t *testing.T) {
	// SEQUENCE with indefinite length containing two INTEGERs
	// 30 80 (SEQUENCE indefinite)
	//   02 01 01 (INTEGER 1)
	//   02 01 02 (INTEGER 2)
	// 00 00 (EOC)
	input, _ := hex.DecodeString("30800201010201020000")
	// Expected: 30 06 02 01 01 02 01 02
	want, _ := hex.DecodeString("3006020101020102")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestNestedIndefiniteLengths(t *testing.T) {
	// Nested indefinite lengths
	// SEQUENCE indefinite containing SEQUENCE indefinite containing INTEGER
	// 30 80 (outer SEQUENCE indefinite)
	//   30 80 (inner SEQUENCE indefinite)
	//     02 01 05 (INTEGER 5)
	//   00 00 (inner EOC)
	// 00 00 (outer EOC)
	input, _ := hex.DecodeString("3080308002010500000000")
	// Expected: 30 05 30 03 02 01 05
	want, _ := hex.DecodeString("30053003020105")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestPrimitiveTypes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "INTEGER positive",
			input: "020105",
			want:  "020105",
		},
		{
			name:  "INTEGER zero",
			input: "020100",
			want:  "020100",
		},
		{
			name:  "NULL",
			input: "0500",
			want:  "0500",
		},
		{
			name:  "OID",
			input: "06032a0304", // 1.2.3.4
			want:  "06032a0304",
		},
		{
			name:  "OCTET STRING primitive",
			input: "0403aabbcc",
			want:  "0403aabbcc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			want, _ := hex.DecodeString(tt.want)

			got, err := MakeDER(input)
			if err != nil {
				t.Fatalf("MakeDER() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MakeDER() = %x, want %x", got, want)
			}
		})
	}
}

func TestApplicationAndPrivateClasses(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Application class primitive",
			input: "4003aabbcc", // [APPLICATION 0] OCTET STRING
			want:  "4003aabbcc",
		},
		{
			name:  "Application class constructed",
			input: "6003020105", // [APPLICATION 0] CONSTRUCTED { INTEGER 5 }
			want:  "6003020105",
		},
		{
			name:  "Private class primitive",
			input: "c003aabbcc", // [PRIVATE 0] OCTET STRING
			want:  "c003aabbcc",
		},
		{
			name:  "Private class constructed",
			input: "e003020105", // [PRIVATE 0] CONSTRUCTED { INTEGER 5 }
			want:  "e003020105",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := hex.DecodeString(tt.input)
			want, _ := hex.DecodeString(tt.want)

			got, err := MakeDER(input)
			if err != nil {
				t.Fatalf("MakeDER() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MakeDER() = %x, want %x", got, want)
			}
		})
	}
}

func TestOtherStringTypes(t *testing.T) {
	// Test other string types that should be flattened
	tests := []struct {
		name     string
		tag      byte
		primTag  byte
		typeName string
	}{
		{name: "NumericString", tag: 0x32, primTag: 0x12, typeName: "NumericString"},     // tag 18
		{name: "TeletexString", tag: 0x34, primTag: 0x14, typeName: "TeletexString"},     // tag 20
		{name: "VideotexString", tag: 0x35, primTag: 0x15, typeName: "VideotexString"},   // tag 21
		{name: "GraphicString", tag: 0x39, primTag: 0x19, typeName: "GraphicString"},     // tag 25
		{name: "VisibleString", tag: 0x3a, primTag: 0x1a, typeName: "VisibleString"},     // tag 26
		{name: "GeneralString", tag: 0x3b, primTag: 0x1b, typeName: "GeneralString"},     // tag 27
		{name: "UniversalString", tag: 0x3c, primTag: 0x1c, typeName: "UniversalString"}, // tag 28
		{name: "BMPString", tag: 0x3e, primTag: 0x1e, typeName: "BMPString"},             // tag 30
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Constructed string with indefinite length containing two primitive chunks
			input := []byte{
				tt.tag, 0x80, // constructed, indefinite length
				tt.primTag, 0x02, 0x41, 0x42, // primitive "AB"
				tt.primTag, 0x02, 0x43, 0x44, // primitive "CD"
				0x00, 0x00, // EOC
			}
			// Expected: primitive with flattened content "ABCD"
			want := []byte{tt.primTag, 0x04, 0x41, 0x42, 0x43, 0x44}

			got, err := MakeDER(input)
			if err != nil {
				t.Fatalf("MakeDER() error for %s = %v", tt.typeName, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MakeDER() for %s = %x, want %x", tt.typeName, got, want)
			}
		})
	}
}

func TestContextSpecificConstructed(t *testing.T) {
	// Context-specific constructed (like IMPLICIT/EXPLICIT tagging)
	// [0] EXPLICIT INTEGER 5
	// A0 03 02 01 05
	input, _ := hex.DecodeString("a003020105")
	want, _ := hex.DecodeString("a003020105")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}

func TestContextSpecificIndefinite(t *testing.T) {
	// Context-specific constructed with indefinite length
	// [0] EXPLICIT indefinite { INTEGER 5 } EOC
	input, _ := hex.DecodeString("a0800201050000")
	// Expected: A0 03 02 01 05
	want, _ := hex.DecodeString("a003020105")

	got, err := MakeDER(input)
	if err != nil {
		t.Fatalf("MakeDER() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MakeDER() = %x, want %x", got, want)
	}
}
