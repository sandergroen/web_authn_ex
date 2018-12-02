defmodule WebAuthnEx.PublicKeyU2f do
  @moduledoc """
  Validates PublicKeyU2f
  """
  alias WebauthnEx.EC2Key
  alias __MODULE__
  @coordinate_length 32

  defstruct [:data]

  def new(data) do
    %PublicKeyU2f{
      data: data
    }
  end

  def valid?(%PublicKeyU2f{} = public_key) do
    byte_size(public_key.data) >= @coordinate_length * 2 &&
      byte_size(cose_key(public_key).x_coordinate) == @coordinate_length &&
      byte_size(cose_key(public_key).y_coordinate) == @coordinate_length &&
      cose_key(public_key).algorithm == -7
  end

  def cose_key(%PublicKeyU2f{} = public_key) do
    EC2Key.from_cbor(public_key.data)
  end

  def to_binary(key) do
    <<4>> <> key.x_coordinate <> key.y_coordinate
  end
end
