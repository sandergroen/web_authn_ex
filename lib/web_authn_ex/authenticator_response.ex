defmodule WebAuthnEx.AuthenticatorResponse do
  alias __MODULE__
  @enforce_keys [:client_data]
  defstruct [:client_data]
  def new(client_data), do: {:ok, %AuthenticatorResponse{client_data: client_data}}

  def valid?(original_challenge, original_origin, attestation, rp_id, client_data_json) do
    authenticator_data = authenticator_data(attestation)
    with true <- valid_type?(client_data_json, "webauthn.create"),
        true <- valid_origin?(original_origin, client_data_json),
        true <- valid_rp_id?(original_origin, authenticator_data, rp_id),
        true <- WebAuthnEx.AuthData.valid?(authenticator_data),
        true <- WebAuthnEx.AuthData.user_flagged?(authenticator_data)
    do
      true
    else
      false -> false
    end
  end

  def valid_origin?(original_origin, client_data_json) do
    {:ok, client_data} = WebAuthnEx.ClientData.new(client_data_json)
    client_data.origin == original_origin
  end

  def authenticator_data(attestation) do
    %{"authData" => auth_data} = attestation
    WebAuthnEx.AuthData.new(auth_data)
  end


  def valid_rp_id?(original_origin, authenticator_data, nil) do
    :crypto.hash(:sha256, rp_id_from_origin(original_origin)) == authenticator_data.rp_id_hash
  end

  def valid_rp_id?(original_origin, authenticator_data, rp_id) do
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
