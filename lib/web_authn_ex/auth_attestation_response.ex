defmodule WebAuthnEx.AuthAttestationResponse do
  alias __MODULE__
  @enforce_keys [:attestation, :credential]
  defstruct [:attestation, :credential]

  def new(attestation_object) do
    attestation = attestation(attestation_object)
    {:ok, %AuthAttestationResponse{attestation: attestation, credential: credential(attestation)}}
  end

  def valid?(original_challenge, original_origin, rp_id, attestation_object, client_data_json) do
    WebAuthnEx.AuthenticatorResponse.valid?(
                original_challenge,
                original_origin,
                attestation(attestation_object),
                rp_id,
                client_data_json
              )
  end

  def credential(attestation) do
    WebAuthnEx.AuthenticatorResponse.authenticator_data(attestation).credential
  end

  def attestation(attestation_object) do
    :cbor.decode(attestation_object)
  end
end
