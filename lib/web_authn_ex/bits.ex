defmodule WebAuthnEx.Bits do
  # Credits: https://minhajuddin.com/2016/11/01/how-to-extract-bits-from-a-binary-in-elixir/
  # this is the public api which allows you to pass any binary representation
  def extract(str) when is_binary(str) do
    str
    |> extract([])
    |> Enum.reverse()
  end

  def insert(bits) when is_list(bits) do
    bits
    |> Enum.reverse()
    |> Enum.into(<<>>, fn bit -> <<bit::1>> end)
  end

  # this function does the heavy lifting by matching the input binary to
  # a single bit and sends the rest of the bits recursively back to itself
  defp extract(<<b::size(1), bits::bitstring>>, acc) when is_bitstring(bits) do
    extract(bits, [b | acc])
  end

  # this is the terminal condition when we don't have anything more to extract
  defp extract(<<>>, acc), do: acc |> Enum.reverse()
end
