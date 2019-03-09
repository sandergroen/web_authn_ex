defmodule WebAuthnEx.MixProject do
  use Mix.Project
  @version "0.1.1"

  @description """
  Implementation of a WebAuthn Relying Party in Elixir.
  """

  def project do
    [
      app: :web_authn_ex,
      version: @version,
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: @description,
      package: package(),
      docs: docs()
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
      {:jason, "~> 1.0"},
      {:credo, "~> 1.0", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp package do
    [
      maintainers: ["Sander Groen"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/sandergroen/web_authn_ex"}
    ]
  end

  defp docs do
    [
      main: "readme",
      name: "WebAuthnEx",
      source_ref: "v#{@version}",
      canonical: "https://hexdocs.pm/web_auth_ex",
      source_url: "https://github.com/sandergroen/web_authn_ex",
      extras: [
        "README.md"
      ]
    ]
  end
end
