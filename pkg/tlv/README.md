# tlv

Package `tlv` implements the Matter Tag-Length-Value (TLV) encoding format (Spec Appendix A).

It provides efficient, low-allocation readers and writers for serializing Go types to and from the wire format.

## Features

*   **Zero-allocation reading**: The `Reader` iterates over bytes without allocating for basic types.
*   **Context & Profile Tags**: Full support for Matter's tag control byte format.
*   **Structure/Array/List**: Helpers for container types.

## Key Types

*   `Writer`: Encodes Go values to a byte stream.
*   `Reader`: Decodes a byte stream into Go values.
*   `Tag`: Represents a TLV tag (Context-specific, Common Profile, or Fully Qualified).

## Supported Data Types

| Matter Type | Go Type | Writer Method | Reader Method |
|-------------|---------|---------------|---------------|
| Signed Int  | `int64` | `PutInt`      | `Int`         |
| Unsigned Int| `uint64`| `PutUint`     | `Uint`        |
| Boolean     | `bool`  | `PutBool`     | `Bool`        |
| Float       | `float32`| `PutFloat`    | `Float`       |
| Double      | `float64`| `PutDouble`   | `Double`      |
| UTF-8 String| `string`| `PutString`   | `String`      |
| Octet String| `[]byte`| `PutBytes`    | `Bytes`       |
| Structure   | -       | `StartStructure`| `EnterContainer`|
| Array       | -       | `StartArray`  | `EnterContainer`|
| List        | -       | `StartList`   | `EnterContainer`|

## Usage

### Writing TLV

```go
import "github.com/backkem/matter/pkg/tlv"

var buf bytes.Buffer
w := tlv.NewWriter(&buf)

// Start a structure with an anonymous tag
w.StartStructure(tlv.Anonymous())

// Field 1: Context-specific tag 1, value 123
w.PutUint(tlv.ContextTag(1), 123)

// Field 2: Context-specific tag 2, string "Hello"
w.PutString(tlv.ContextTag(2), "Hello")

w.EndContainer()
```

### Reading TLV

```go
r := tlv.NewReader(bytes.NewReader(data))

// Iterate over elements
for {
    err := r.Next()
    if err != nil { // Handle EOF or error
        break 
    }

    // Check tag
    if r.Tag().Equal(tlv.ContextTag(1)) {
        val, _ := r.Uint()
        fmt.Printf("Value: %d\n", val)
    }
}
```