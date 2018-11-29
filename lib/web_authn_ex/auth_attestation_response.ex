defmodule WebAuthnEx.AuthAttestationResponse do
  alias __MODULE__
  @enforce_keys [:attestation, :credential]
  defstruct [:attestation, :credential]

  def new(attestation_object) do
    attestation = attestation(attestation_object)
    {:ok, %AuthAttestationResponse{attestation: attestation, credential: credential(attestation)}}
  end

  def valid?(original_challenge, original_origin, rp_id, attestation_object, client_data_json) do
    attestation = attestation(attestation_object)
    attestation_statement = attestation_statement(attestation)
    {:ok, client_data} = WebAuthnEx.ClientData.new(client_data_json)

    WebAuthnEx.AuthenticatorResponse.valid?(
      original_challenge,
      original_origin,
      attestation,
      rp_id,
      client_data_json
    ) &&
      WebAuthnEx.AttestationStatement.valid?(
        attestation["fmt"],
        authenticator_data(attestation),
        client_data.hash,
        attestation_statement
      )
  end

  def attestation_statement(attestation) do
    {:ok, statement} =
      WebAuthnEx.AttestationStatement.from(attestation["fmt"], attestation["attStmt"])

    statement
  end

  def authenticator_data(attestation) do
    WebAuthnEx.AuthenticatorResponse.authenticator_data(attestation)
  end

  defp credential(attestation) do
    authenticator_data(attestation).credential
  end

  defp attestation(attestation_object) do
    :cbor.decode(attestation_object)
  end
end
