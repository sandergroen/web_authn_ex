defmodule WebAuthnEx.Cbor.Types do
  @unsigned_integer <<0b000::3>>
  @negative_integer <<0b001::3>>
  @byte_string <<0b010::3>>
  @string <<0b011::3>>
  @map <<0b101::3>>
  @array <<0b100::3>>

  def unsigned_integer, do: @unsigned_integer
  def negative_integer, do: @negative_integer
  def byte_string, do: @byte_string
  def string, do: @string
  def map, do: @map
  def array, do: @array
end
