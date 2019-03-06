defmodule WebAuthnEx.Cbor.Decoder do
  alias WebAuthnEx.Cbor.Types

  @unsigned_integer Types.unsigned_integer()
  @negative_integer Types.negative_integer()
  @string Types.string()
  @array Types.array()
  @byte_string Types.byte_string()
  @map Types.map()

  def decode(value) do
    {value, rest} = read(value)

    if rest == <<>> do
      {:ok, value}
    else
      {:error, :invalid_trailing_data}
    end
  end

  defp read(<<@unsigned_integer, bits::bits>>), do: read_unsigned_integer(bits)
  defp read(<<@negative_integer, bits::bits>>), do: read_negative_integer(bits)
  defp read(<<@string, bits::bits>>), do: read_binary(bits)
  defp read(<<@byte_string, bits::bits>>), do: read_binary(bits)
  defp read(<<@array, bits::bits>>), do: read_array(bits)
  defp read(<<@map, bits::bits>>), do: read_map(bits)

  defp read_binary(value) do
    {length, rest} = read_unsigned_integer(value)
    <<value::binary-size(length), rest::binary>> = rest
    {value, rest}
  end

  def read_map(value) do
    {size, rest} = read_unsigned_integer(value)

    if size == 0 do
      {%{}, rest}
    else
      {map, rest} =
        Enum.reduce(1..size, {%{}, rest}, fn _, acc ->
          {key, rest} = read(elem(acc, 1))
          {value, rest} = read(rest)
          {Map.put(elem(acc, 0), key, value), rest}
        end)

      {map, rest}
    end
  end

  defp read_array(value) do
    {length, rest} = read_unsigned_integer(value)

    if length == 0 do
      {[], rest}
    else
      {values, rest} =
        Enum.reduce(1..length, {[], rest}, fn _, {acc, rest} ->
          {value, rest} = read(rest)
          {[value | acc], rest}
        end)

      {values |> Enum.reverse(), rest}
    end
  end

  defp read_unsigned_integer(<<27::size(5), value::size(64), rest::bits>>), do: {value, rest}
  defp read_unsigned_integer(<<26::size(5), value::size(32), rest::bits>>), do: {value, rest}
  defp read_unsigned_integer(<<25::size(5), value::size(16), rest::bits>>), do: {value, rest}
  defp read_unsigned_integer(<<24::size(5), value::size(8), rest::bits>>), do: {value, rest}
  defp read_unsigned_integer(<<(<<value::size(5)>>)::bitstring, rest::bits>>), do: {value, rest}

  defp read_negative_integer(value) do
    {unsigned, rest} = read_unsigned_integer(value)
    {unsiged_to_negative(unsigned), rest}
  end

  defp unsiged_to_negative(unsined_value), do: (unsined_value + 1) * -1
end
