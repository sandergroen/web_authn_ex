defmodule WebAuthnEx.MixProject do
  use Mix.Project
  @version "0.1.0"

  @description """
  WebAuthn library for Elixir.
  """

  def project do
    [
      app: :web_authn_ex,
      version: @version,
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      name: "WebAuthnEx",
      description: @description,
      source_url: "https://github.com/sandergroen/web_authn_ex",
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:cbor_ex, github: "sandergroen/cbor_ex"},
      {:jason, "~> 1.0"},
    ]
  end
end
