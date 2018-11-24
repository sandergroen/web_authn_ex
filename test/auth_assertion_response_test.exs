defmodule AuthAssertionResponseTest do
  use ExUnit.Case
  doctest WebAuthnEx.AuthAssertionResponse

  test "valid_signature attestation_response" do
    params = :crypto.ec_curve(:prime256v1)
    {public_key_bytes, private_key} = :crypto.generate_key(:ecdh, :prime256v1)
    client_data_json = client_json()
    auth_data = auth_data()
    hash = auth_data <> :crypto.hash(:sha256, client_data_json)
    signature = :crypto.sign(:ecdsa, :sha256, hash, [private_key, params])

    WebAuthnEx.AuthAssertionResponse.valid_signature?(
      public_key_bytes,
      signature,
      client_data_json,
      auth_data
    )
  end

  def client_json do
    %{challenge: challenge(), origin: "http://localhost", type: "webauthn.get"} |> Jason.encode!()
  end

  def challenge do
    32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

  def auth_data do
    rp_id_hash() <> flags() <> <<0::size(32)>> <> <<"">>
  end

  def flags do
    [1, 0, 1, 0, 0, 0, 1, 0]
    |> WebAuthnEx.Bits.insert()
  end

  def rp_id_hash do
    :crypto.hash(:sha256, "localhost")
  end
end
