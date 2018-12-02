defmodule FakeAuthenticator do
  alias __MODULE__
  @enforce_keys [:challenge, :rp_id, :sign_count, :context, :type]
  defstruct [:challenge, :rp_id, :sign_count, :context, :type]

  def get(options \\ %{context: %{}}) do
    context = %{attested_credential_data_present: false}
    |> Map.merge(options.context)

    %{challenge: fake_challenge(), rp_id: "localhost", sign_count: 0}
    |> Map.merge(options)
    |> Map.put(:context, context)
    |> new("webauthn.get")
    |> signature()
  end

  def create(options \\ %{context: %{}}) do
    context = %{attested_credential_data_present: true}
    |> Map.merge(options.context)

    %{challenge: fake_challenge(), rp_id: "localhost", sign_count: 0}
    |> Map.merge(options)
    |> Map.put(:context, context)
    |> new("webauthn.create")
    |> attestation_object()
  end

  defp new(options, type) do
    %FakeAuthenticator{
      challenge: options.challenge,
      rp_id: options.rp_id,
      sign_count: options.sign_count,
      context: options.context,
      type: type
    }
    |> raw_flags()
    |> credential_key()
    |> credential_id()
    |> authenticator_data()
    |> origin()
    |> client_data_json()
  end

  def authenticator_data(%FakeAuthenticator{} = authenticator) do
    authenticator
    |> Map.put(
      :authenticator_data,
      rp_id_hash(authenticator.rp_id) <>
        authenticator.flags <>
        raw_sign_count(authenticator.sign_count) <> attested_credential_data(authenticator)
    )
  end

  def client_data_json(%FakeAuthenticator{} = authenticator) do
    authenticator
    |> Map.put(
      :client_data_json,
      %{
        challenge: encode(authenticator.challenge),
        origin: authenticator.origin,
        type: authenticator.type
      }
      |> Jason.encode!()
    )
  end

  def credential_key(%FakeAuthenticator{} = authenticator) do
    authenticator
    |> Map.put(:credential_key, :crypto.generate_key(:ecdh, :prime256v1))
  end

  def raw_flags(%FakeAuthenticator{} = authenticator) do
    authenticator
    |> Map.put(
      :flags,
      [
        bit(:user_present, authenticator.context),
        0,
        bit(:user_verified, authenticator.context),
        0,
        0,
        0,
        bit(:attested_credential_data_present, authenticator.context),
        0
      ]
      |> WebAuthnEx.Bits.insert()
    )
  end

  def raw_sign_count(sign_count) do
    <<sign_count::size(32)>>
  end

  def credential_id(%FakeAuthenticator{} = authenticator) do
    authenticator |> Map.put(:credential_id, 16 |> :crypto.strong_rand_bytes())
  end

  def rp_id_hash(rp_id) do
    :crypto.hash(:sha256, rp_id)
  end

  def origin(%FakeAuthenticator{} = authenticator) do
    authenticator
    |> Map.put(:origin, authenticator.context[:origin] || fake_origin())
  end

  def bit(flag, context) do
    case context[flag] do
      nil -> 1
      true -> 1
      _ -> 0
    end
  end

  defp attestation_object(%FakeAuthenticator{} = authenticator) do
    authenticator
    |> Map.put(
      :attestation_object,
      CborEx.encode(%{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => authenticator.authenticator_data
      })
    )
  end

  defp attested_credential_data(%FakeAuthenticator{} = authenticator) do
    case authenticator.type do
      "webauthn.create" ->
        aaguid() <>
          <<byte_size(authenticator.credential_id)::size(16)>> <>
          authenticator.credential_id <> cose_credential_public_key(authenticator)

      _ ->
        <<"">>
    end
  end

  defp cose_credential_public_key(%FakeAuthenticator{} = authenticator) do
    {public_key, _} = authenticator.credential_key

    x_coordinate =
      public_key |> :binary.bin_to_list() |> Enum.slice(1..32) |> :binary.list_to_bin()

    y_coordinate =
      public_key |> :binary.bin_to_list() |> Enum.slice(33..64) |> :binary.list_to_bin()

    fake_cose_credential_key(%{
      algorithm: nil,
      x_coordinate: x_coordinate,
      y_coordinate: y_coordinate
    })
  end

  defp aaguid do
    16 |> :crypto.strong_rand_bytes()
  end

  def fake_origin do
    "http://localhost"
  end

  def fake_challenge do
    32 |> :crypto.strong_rand_bytes()
  end

  defp encode(value) do
    value |> Base.url_encode64(padding: false)
  end

  defp signature(%FakeAuthenticator{} = authenticator) do
    params = :crypto.ec_curve(:prime256v1)
    {_, private_key} = authenticator.credential_key

    hash =
      authenticator.authenticator_data <> :crypto.hash(:sha256, authenticator.client_data_json)

    authenticator
    |> Map.put(:signature, :crypto.sign(:ecdsa, :sha256, hash, [private_key, params]))
  end

  def fake_cose_credential_key(options \\ %{algorithm: nil, x_coordinate: nil, y_coordinate: nil}) do
    kty_label = 1
    alg_label = 3
    crv_label = -1
    x_label = -2
    y_label = -3

    kty_ec2 = 2
    alg_es256 = -7
    crv_p256 = 1

    CborEx.encode(%{
      kty_label => kty_ec2,
      alg_label => options.algorithm || alg_es256,
      crv_label => crv_p256,
      x_label => options.x_coordinate || :crypto.strong_rand_bytes(32),
      y_label => options.y_coordinate || :crypto.strong_rand_bytes(32)
    })
  end
end
