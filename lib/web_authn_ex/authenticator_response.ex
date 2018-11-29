defmodule WebAuthnEx.AuthenticatorResponse do
  @moduledoc """
  Validates authenticator
  """
  alias __MODULE__
  @enforce_keys [:client_data]
  defstruct [:client_data]
  def new(client_data), do: {:ok, %AuthenticatorResponse{client_data: client_data}}

  def valid?(original_challenge, original_origin, attestation, rp_id, client_data_json) do
    authenticator_data = authenticator_data(attestation)
    {:ok, client_data} = WebAuthnEx.ClientData.new(client_data_json)

    auth_data =
      case is_binary(attestation) do
        true -> attestation
        false -> attestation["authData"]
      end

    with true <- valid_type?(client_data_json, client_data.type),
         true <- valid_challenge?(original_challenge, client_data),
         true <- valid_origin?(original_origin, client_data),
         true <- valid_rp_id?(original_origin, authenticator_data, rp_id),
         true <- WebAuthnEx.AuthData.valid?(authenticator_data, auth_data),
         true <- WebAuthnEx.AuthData.user_flagged?(authenticator_data) do
      true
    else
      false -> false
    end
  end

  def valid_challenge?(original_challenge, client_data) do
    Base.url_decode64!(client_data.challenge, padding: false) == original_challenge
  end

  def valid_origin?(original_origin, client_data) do
    client_data.origin == original_origin
  end

  def authenticator_data(authenticator_data) when is_binary(authenticator_data) do
    WebAuthnEx.AuthData.new(authenticator_data)
  end

  def authenticator_data(%{"authData" => auth_data} = authenticator_data)
      when is_map(authenticator_data) do
    auth_data |> WebAuthnEx.AuthData.new()
  end

  def valid_rp_id?(original_origin, authenticator_data, nil) do
    case rp_id_from_origin(original_origin) do
      {:ok, host} ->
        :crypto.hash(:sha256, host) == authenticator_data.rp_id_hash

      {:error, nil} ->
        false
    end
  end

  def valid_rp_id?(_, authenticator_data, rp_id) do
    :crypto.hash(:sha256, rp_id) == authenticator_data.rp_id_hash
  end

  def valid_type?(client_data_json, type) do
    {:ok, client_data} = WebAuthnEx.ClientData.new(client_data_json)
    client_data.type == type
  end

  def rp_id_from_origin(origin) when origin == nil do
    {:error, nil}
  end

  def rp_id_from_origin(origin) do
    case URI.parse(origin) do
      %URI{host: nil} -> {:error, nil}
      %URI{host: host} -> {:ok, host}
    end
  end
end
