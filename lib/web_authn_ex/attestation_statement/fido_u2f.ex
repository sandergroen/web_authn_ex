defmodule WebAuthnEx.AttestationStatement.FidoU2f do
  @moduledoc """
  Verifies FidoU2F attestation statement
  """
  alias __MODULE__
  @enforce_keys [:statement]
  defstruct [:statement]
  def new(statement), do: {:ok, %FidoU2f{statement: statement}}
  @valid_attestation_certificate_count 1

  def valid?(authenticator_data, client_data_hash, %FidoU2f{} = fido2) do
    valid_format?(fido2) && valid_certificate_public_key?(fido2) &&
      valid_signature?(authenticator_data, client_data_hash, fido2)
  end

  def valid_certificate_public_key?(fido2) do
    case fido2 |> certificate() |> public_key() do
      {:ok, _} ->
        true

      {:error, _} ->
        false
    end
  end

  def certificate(fido2) do
    :public_key.pkix_decode_cert(Enum.at(fido2.statement["x5c"], 0), :otp)
  end

  def public_key(certificate) do
    public_key = certificate |> elem(1) |> elem(7) |> elem(2)

    case public_key do
      {:ECPoint, _} ->
        {:ok, {public_key, {:namedCurve, :prime256v1}}}

      _ ->
        {:error, "no matching key"}
    end
  end

  def valid_format?(fido2) do
    !!(fido2.statement["x5c"] && fido2.statement["sig"]) &&
      length(fido2.statement["x5c"]) == @valid_attestation_certificate_count
  end

  def signature(fido2) do
    fido2.statement["sig"]
  end

  def valid_signature?(authenticator_data, client_data_hash, fido2) do
    signature = signature(fido2)
    {:ok, public_key} = fido2 |> certificate() |> public_key()
    verification_data = verification_data(authenticator_data, client_data_hash)
    :public_key.verify(verification_data, :sha256, signature, public_key)
  end

  def verification_data(authenticator_data, client_data_hash) do
    {{:ECPoint, public_key}, {:namedCurve, :prime256v1}} =
      authenticator_data.credential.public_key

    <<0>> <>
      authenticator_data.rp_id_hash <>
      client_data_hash <> authenticator_data.credential.id <> public_key
  end
end
