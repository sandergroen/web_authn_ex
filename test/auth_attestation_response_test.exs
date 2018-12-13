defmodule AuthAttestationResponseTest do
  use ExUnit.Case
  doctest WebAuthnEx.AuthAttestationResponse
  alias WebAuthnEx.AuthAttestationResponse

  test "is valid if everything's in place" do
    original_challenge = FakeAuthenticator.fake_challenge()
    origin = FakeAuthenticator.fake_origin()

    authenticator =
      FakeAuthenticator.create(%{challenge: original_challenge, context: %{origin: origin}})

    {:ok, auth_attestation_response} =
      AuthAttestationResponse.new(
        original_challenge,
        origin,
        authenticator.attestation_object,
        authenticator.client_data_json,
        authenticator.rp_id
      )

    credential = auth_attestation_response.credential
    assert is_binary(credential.id)

    {{:ECPoint, public_key}, {:namedCurve, :prime256v1}} = credential.public_key
    assert is_binary(public_key)
  end

  test "can validate fido-u2f attestation" do
    original_origin = "http://localhost:3000"

    {:ok, original_challenge} =
      "11CzaFXezx7YszNaYE3pag=="
      |> Base.decode64()

    {:ok, attestation_object} =
      "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgekOQZSd0/dNZZ3iBBaKWUVaYx49+w37LunPGKthcYG8CICFt3JdafYmqC3oAHDeFkLYM0eQjWPjZkh7WBqvRCcR9Y3g1Y4FZAsIwggK+MIIBpqADAgECAgR0hv3CMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxOTU1MDAzODQyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElV3zrfckfTF17/2cxPMaToeOuuGBCVZhUPs4iy5fZSe/V0CapYGlDQrFLxhEXAoTVIoTU8ik5ZpwTlI7wE3r7aNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ+KAR84wKTRWABhcRH57cfTAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAxXEiA5ppSfjhmib1p/Qqob0nrnk6FRUFVb6rQCzoAih3cAflsdvZoNhqR4jLIEKecYwdMm256RusdtdhcREifhop2Q9IqXIYuwD8D5YSL44B9es1V+OGuHuITrHOrSyDj+9UmjLB7h4AnHR9L4OXdrHNNOliXvU1zun81fqIIyZ2KTSkC5gl6AFxNyQTcChgSDgr30Az8lpoohuWxsWHz7cvGd6Z41/tTA5zNoYa+NLpTMZUjQ51/2Upw8jBiG5PEzkJo0xdNlDvGrj/JN8LeQ9a0TiEVPfhQkl+VkGIuvEbg6xjGQfD+fm8qCamykHcZ9i5hNaGQMqITwJi3KDzuaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABA2Nc6mqO+eIH0eIAhy1xfIJcjHtlOAsRLHxf4u5apXnhI6j8oGbmF87Qz6L8AvGjlHQLjGhAXjLpBFb2aeVowSqUBAgMmIAEhWCBsj3dTr9jqWWOwuDzWAQOqqugB1YGYKpE/YqHfRB3GrCJYIPiyHJ4rYZRaqfJQKAInKzINuxkQARzVdNcChyszi/Pr"
      |> Base.decode64()

    {:ok, client_data_json} =
      "eyJjaGFsbGVuZ2UiOiIxMUN6YUZYZXp4N1lzek5hWUUzcGFnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
      |> Base.decode64()

    assert {:ok, auth_attestation_response} =
             AuthAttestationResponse.new(
               original_challenge,
               original_origin,
               attestation_object,
               client_data_json,
               "localhost"
             )
  end

  test "origin validation matches the default one" do
    original_challenge = FakeAuthenticator.fake_challenge()
    original_origin = FakeAuthenticator.fake_origin()

    authenticator =
      %{challenge: original_challenge, context: %{origin: original_origin}}
      |> FakeAuthenticator.create()

    origin = "http://localhost"

    assert {:ok, auth_attestation_response} =
             AuthAttestationResponse.new(
               original_challenge,
               origin,
               authenticator.attestation_object,
               authenticator.client_data_json,
               "localhost"
             )
  end

  test "origin validation doesn't match the default one" do
    original_challenge = FakeAuthenticator.fake_challenge()
    original_origin = FakeAuthenticator.fake_origin()

    authenticator =
      %{challenge: original_challenge, context: %{origin: original_origin}}
      |> FakeAuthenticator.create()

    origin = "http://invalid"

    assert {:error, "Validation of authenticator failed!"} =
             AuthAttestationResponse.new(
               original_challenge,
               origin,
               authenticator.attestation_object,
               authenticator.client_data_json,
               "localhost"
             )
  end

  test "rp_id validation matches the default one" do
    original_challenge = FakeAuthenticator.fake_challenge()
    original_origin = FakeAuthenticator.fake_origin()
    rp_id = "localhost"

    authenticator =
      %{challenge: original_challenge, rp_id: rp_id, context: %{origin: original_origin}}
      |> FakeAuthenticator.create()

    assert {:ok, auth_attestation_response} =
             AuthAttestationResponse.new(
               original_challenge,
               original_origin,
               authenticator.attestation_object,
               authenticator.client_data_json,
               "localhost"
             )
  end

  test "rp_id validation doesn't match the default one" do
    original_challenge = FakeAuthenticator.fake_challenge()
    original_origin = FakeAuthenticator.fake_origin()
    rp_id = "invalid"

    authenticator =
      %{challenge: original_challenge, rp_id: rp_id, context: %{origin: original_origin}}
      |> FakeAuthenticator.create()

    assert {:error, "Validation of authenticator failed!"} =
             AuthAttestationResponse.new(
               original_challenge,
               original_origin,
               authenticator.attestation_object,
               authenticator.client_data_json,
               "localhost"
             )
  end

  test "rp_id validation matches one explicitly given" do
    original_challenge = FakeAuthenticator.fake_challenge()
    original_origin = FakeAuthenticator.fake_origin()
    rp_id = "custom"

    authenticator =
      %{challenge: original_challenge, rp_id: rp_id, context: %{origin: original_origin}}
      |> FakeAuthenticator.create()

    assert {:ok, auth_attestation_response} =
             AuthAttestationResponse.new(
               original_challenge,
               original_origin,
               authenticator.attestation_object,
               authenticator.client_data_json,
               "custom"
             )
  end
end
