defmodule AuthenticatorTest do
  use ExUnit.Case
  doctest WebAuthnEx.AuthData
  alias WebAuthnEx.AuthData

  @rp_id "localhost"
  @sign_count 42
  @user_present true
  @user_verified false
  @authenticator FakeAuthenticator.create(%{
    challenge: FakeAuthenticator.fake_challenge(),
    rp_id: @rp_id,
    sign_count: @sign_count,
    context: %{
      user_present: @user_present,
      user_verified: @user_verified,
      attested_credential_data_present: true
    }
  })
  @authenticator_data AuthData.new(@authenticator.authenticator_data)

  test "#rp_id_hash" do
    assert @authenticator_data.rp_id_hash == FakeAuthenticator.rp_id_hash(@rp_id)
  end

  test "#sign_count" do
    assert @authenticator_data.sign_count == 42
  end

  test "#user_present? when UP flag is set" do
    assert AuthData.user_present?(@authenticator_data)
  end

  test "when UP flag is not set" do
    refute false
    |> authenticator(@user_verified)
    |> authenticator_data()
    |> AuthData.user_present?()
  end

  test "#user_verified? when UV flag is set" do
    assert @user_present
    |> authenticator(true)
    |> authenticator_data()
    |> AuthData.user_verified?()
  end

  test "#user_verified? when UV flag not is set" do
    refute @user_present
    |> authenticator(false)
    |> authenticator_data()
    |> AuthData.user_verified?()
  end

  test "#user_flagged? when both UP and UV flag are set" do
    assert true
    |> authenticator(true)
    |> authenticator_data()
    |> AuthData.user_flagged?()
  end

  test "#user_flagged? when only UP is set" do
    assert true
    |> authenticator(false)
    |> authenticator_data()
    |> AuthData.user_flagged?()
  end

  test "#user_flagged? when only UV flag is set" do
    assert false
    |> authenticator(true)
    |> authenticator_data()
    |> AuthData.user_flagged?()
  end

  test "#user_flagged? when both UP and UV flag are not set" do
    refute false
    |> authenticator(false)
    |> authenticator_data()
    |> AuthData.user_flagged?()
  end

  defp authenticator(user_present, user_verified) do
    FakeAuthenticator.create(%{
      challenge: FakeAuthenticator.fake_challenge(),
      rp_id: @rp_id,
      sign_count: @sign_count,
      context: %{
        user_present: user_present,
        user_verified: user_verified,
        attested_credential_data_present: true
      }
    })
  end

  defp authenticator_data(authenticator) do
    authenticator.authenticator_data
    |> AuthData.new()
  end
end
