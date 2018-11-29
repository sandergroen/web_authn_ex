defmodule WebAuthnEx.PublicKeyU2f do
  @coordinate_length 32

  def valid?(data) do
    cose_key = cose_key(data)

    byte_size(data) >= @coordinate_length * 2 &&
      byte_size(cose_key.x_coordinate) == @coordinate_length &&
      byte_size(cose_key.y_coordinate) == @coordinate_length && cose_key.algorithm == -7
  end

  def cose_key(data) do
    WebauthnEx.EC2Key.from_cbor(data)
  end

  def to_str(key) do
    <<4>> <> key.x_coordinate <> key.y_coordinate
  end
end
