defmodule WebAuthnEx.Cbor.Encoder do
  @moduledoc """
  Encodes CBOR objects.
  """
  alias WebAuthnEx.Cbor.Types

  def encode(value) do
    case value do
      value when is_integer(value) and value >= 0 ->
        concat(Types.unsigned_integer(), encode_unsigned_int(value))

      value when is_integer(value) ->
        concat(Types.negative_integer(), encode_negative_int(value))

      value when is_atom(value) ->
        concat(Types.string(), encode_string(value))

      value when is_binary(value) ->
        concat(Types.byte_string(), encode_byte_string(value))

      value when is_list(value) ->
        concat(Types.array(), encode_array(value))

      value when is_map(value) ->
        concat(Types.map(), encode_map(value))
    end
  end

  def concat(left, right) do
    <<left::bitstring, right::bitstring>>
  end

  def encode_byte_string(value) do
    length = encode_unsigned_int(byte_size(value))

    concat(length, value)
  end

  def encode_array(value) do
    length = encode_unsigned_int(length(value))
    values = value |> Enum.map(&encode/1) |> Enum.join()

    concat(length, values)
  end

  def encode_map(value) do
    length = encode_unsigned_int(map_size(value))

    values =
      value
      |> Map.keys()
      |> Enum.map(fn key ->
        concat(encode(key), encode(value[key]))
      end)
      |> Enum.reduce(<<>>, &concat/2)

    concat(length, values)
  end

  def encode_string(value) do
    string = to_string(value)
    length = encode_unsigned_int(String.length(string))
    concat(length, string)
  end

  def encode_unsigned_int(value) do
    case value do
      value when value in 0..23 ->
        <<value::size(5)>>

      value when value in 24..0x0FF ->
        <<24::size(5), value>>

      value when value in 0x100..0x0FFFF ->
        <<25::size(5), value::size(16)>>

      value when value in 0x10000..0x0FFFFFFFF ->
        <<26::size(5), value::size(32)>>

      value when value in 0x100000000..0x0FFFFFFFFFFFFFFFF ->
        <<27::size(5), value::size(64)>>
    end
  end

  def encode_negative_int(value) do
    unsigned_value = value * -1 - 1

    case unsigned_value do
      unsigned_value when unsigned_value in 0..23 ->
        <<unsigned_value + 32::5>>

      unsigned_value when unsigned_value in 24..0x0FF ->
        <<56::size(5), unsigned_value>>

      unsigned_value when unsigned_value in 0x100..0x0FFFF ->
        <<57::size(5), unsigned_value::size(16)>>

      unsigned_value when unsigned_value in 0x10000..0x0FFFFFFFF ->
        <<58::size(5), unsigned_value::size(32)>>

      unsigned_value when unsigned_value in 0x100000000..0x0FFFFFFFFFFFFFFFF ->
        <<59::size(5), unsigned_value::size(64)>>
    end
  end
end
