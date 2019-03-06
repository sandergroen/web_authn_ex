defmodule WebAuthnEx.AuthData do
  @moduledoc """
  Validates authenticator data
  """
  alias WebAuthnEx.{Bits, Credential}
  alias __MODULE__

  @rp_id_hash_position 0
  @rp_id_hash_length 32
  @flags_length 1
  @sign_count_length 4
  @sign_count_position 33
  @user_present_flag_position 0
  @user_verified_flag_position 2
  @attested_credential_data_included_flag_position 6

  defstruct [:credential, :rp_id_hash, :sign_count, :flags]

  def new(auth_data) do
    %AuthData{
      credential: credential(auth_data),
      rp_id_hash: rp_id_hash(auth_data),
      sign_count: sign_count(auth_data),
      flags: flags(auth_data)
    }
  end

  def valid?(%AuthData{} = auth_data, data) do
    length = byte_size(data) - base_length()
    credential_data = data |> :binary.part(base_length(), length)

    case attested_credential_data?(auth_data) do
      true -> byte_size(data) > base_length() && Credential.valid?(credential_data)
      false -> byte_size(data) == base_length()
    end
  end

  def user_flagged?(%AuthData{} = auth_data) do
    user_present?(auth_data) || user_verified?(auth_data)
  end

  def user_present?(%AuthData{} = auth_data) do
    Enum.at(auth_data.flags, @user_present_flag_position) == 1
  end

  def user_verified?(%AuthData{} = auth_data) do
    Enum.at(auth_data.flags, @user_verified_flag_position) == 1
  end

  def attested_credential_data?(%AuthData{} = auth_data) do
    Enum.at(auth_data.flags, @attested_credential_data_included_flag_position) == 1
  end

  def credential(auth_data) do
    length = byte_size(auth_data) - base_length()

    auth_data
    |> :binary.part(base_length(), length)
    |> Credential.new()
  end

  defp rp_id_hash(auth_data) do
    auth_data
    |> :binary.part(@rp_id_hash_position, @rp_id_hash_length)
  end

  defp base_length do
    @rp_id_hash_length + @flags_length + @sign_count_length
  end

  defp sign_count(data) do
    <<number::big-integer-size(32)>> =
      data |> :binary.part(@sign_count_position, @sign_count_length)

    number
  end

  defp flags(data) do
    data
    |> :binary.part(@rp_id_hash_length, @flags_length)
    |> Bits.extract()
  end
end
