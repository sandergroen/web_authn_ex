defmodule WebAuthnEx.AuthAttestationResponse do
  @moduledoc """
  Validates attestation
  """
  alias __MODULE__
  alias WebAuthnEx.{AttestationStatement, AuthenticatorResponse, ClientData}

  @enforce_keys [
    :original_challenge,
    :original_origin,
    :attestation,
    :attestation_statement,
    :credential,
    :client_data_json,
    :rp_id
  ]
  defstruct [
    :original_challenge,
    :original_origin,
    :attestation,
    :attestation_statement,
    :credential,
    :client_data_json,
    :rp_id,
    :valid_authenticator,
    :valid_attestation_statement,
    :client_data
  ]

  def new(original_challenge, original_origin, attestation_object, client_data_json, rp_id \\ nil) do
    attestation = attestation(attestation_object)
    attestation_statement = attestation_statement(attestation)
    client_data = ClientData.new(client_data_json)

    case client_data do
      {:ok, client_data} ->
        %AuthAttestationResponse{
          original_challenge: original_challenge,
          original_origin: original_origin,
          attestation: attestation,
          attestation_statement: attestation_statement,
          credential: credential(attestation),
          client_data_json: client_data_json,
          rp_id: rp_id,
          client_data: client_data
        }
        |> valid?()
        |> result()

      {:error, reason} ->
        {:error, reason}
    end
  end

  def result(
        %AuthAttestationResponse{
          valid_authenticator: valid_authenticator,
          valid_attestation_statement: valid_attestation_statement
        } = auth_attestation_response
      ) do
    cond do
      valid_authenticator == false ->
        {:error, "Validation of authenticator failed!"}

      valid_attestation_statement == false ->
        {:error, "Validation of attestation statement failed!"}

      true ->
        {:ok, auth_attestation_response}
    end
  end

  def valid?(%AuthAttestationResponse{} = auth_attestation_response) do
    auth_attestation_response
    |> valid_authenticator_response?()
    |> valid_attestation_statement?()
  end

  def valid_authenticator_response?(%AuthAttestationResponse{} = auth_attestation_response) do
    case AuthenticatorResponse.valid?(
           auth_attestation_response.original_challenge,
           auth_attestation_response.original_origin,
           auth_attestation_response.attestation,
           auth_attestation_response.rp_id,
           auth_attestation_response.client_data_json
         ) do
      true ->
        %AuthAttestationResponse{auth_attestation_response | valid_authenticator: true}

      false ->
        %AuthAttestationResponse{auth_attestation_response | valid_authenticator: false}
    end
  end

  def valid_attestation_statement?(%AuthAttestationResponse{} = auth_attestation_response) do
    case AttestationStatement.valid?(
           auth_attestation_response.attestation["fmt"],
           authenticator_data(auth_attestation_response.attestation),
           auth_attestation_response.client_data.hash,
           auth_attestation_response.attestation_statement
         ) do
      true ->
        %AuthAttestationResponse{auth_attestation_response | valid_attestation_statement: true}

      false ->
        %AuthAttestationResponse{auth_attestation_response | valid_attestation_statement: false}
    end
  end

  def attestation_statement(attestation) do
    {:ok, statement} = AttestationStatement.from(attestation["fmt"], attestation["attStmt"])
    statement
  end

  def authenticator_data(attestation) do
    AuthenticatorResponse.authenticator_data(attestation)
  end

  defp credential(attestation) do
    authenticator_data(attestation).credential
  end

  defp attestation(attestation_object) do
    :cbor.decode(attestation_object)
  end
end
