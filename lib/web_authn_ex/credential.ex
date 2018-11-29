defmodule WebAuthnEx.Credential do
  @moduledoc """
  WebAuthnEx.Credential creates public key from binary data
  """
  alias WebAuthnEx.PublicKeyU2f
  @aaguid_length 16
  @id_length 2

  alias __MODULE__
  defstruct [:id, :credential]

  def new(auth_data) do
    %Credential{
      id: id(auth_data),
      credential: credential(auth_data)
    }
  end

  def credential(auth_data) do
    if id(auth_data) do
      {{:ECPoint, public_key(auth_data)}, {:namedCurve, :prime256v1}}
    end
  end

  def public_key(auth_data) do
    PublicKeyU2f.to_str(
      PublicKeyU2f.cose_key(
        data_at(auth_data, public_key_position(auth_data), public_key_length(auth_data))
      )
    )
  end

  def public_key_position(auth_data) do
    id_position() + id_length(auth_data)
  end

  def public_key_length(auth_data) do
    byte_size(auth_data) + @aaguid_length + @id_length + id_length(auth_data)
  end

  def id(auth_data) do
    if valid?(auth_data) do
      data_at(auth_data, id_position(), id_length(auth_data))
    end
  end

  def id_position do
    @aaguid_length + @id_length
  end

  def id_length(auth_data) do
    <<number::big-integer-size(16)>> = data_at(auth_data, @aaguid_length, @id_length)
    number
  end

  def valid?(data) do
    byte_size(data) >= @aaguid_length + @id_length
  end

  defp data_at(data, pos, length) do
    data
    |> :binary.bin_to_list()
    |> Enum.slice(pos..(pos + length - 1))
    |> :binary.list_to_bin()
  end
end
