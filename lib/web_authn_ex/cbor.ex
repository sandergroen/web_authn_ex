defmodule WebAuthnEx.Cbor do
  @moduledoc """
  Implementation of CBOR (rfc7049) encoder and decoder.
  """
  alias WebAuthnEx.Cbor.{Decoder, Encoder}

  def encode(value) do
    Encoder.encode(value)
  end

  def decode!(value) do
    {:ok, result} = decode(value)

    result
  end

  def decode(value) do
    Decoder.decode(value)
  end
end
