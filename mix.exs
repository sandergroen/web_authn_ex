defmodule WebAuthnEx.MixProject do
  use Mix.Project
  @version "0.1.0"

  @description """
  Implementation of a WebAuthn Relying Party in Elixir.
  """

  def project do
    [
      app: :web_authn_ex,
      version: @version,
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      name: "WebAuthnEx",
      description: @description,
      docs: [
        main: "readme",
        source_url: "https://github.com/sandergroen/web_authn_ex",
        extras: [
          "README.md"
        ]
      ],
      source_url: "https://github.com/sandergroen/web_authn_ex",
      deps: deps(),
      package: package()
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
      {:credo, "~> 1.0", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Sander Groen"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/sandergroen/web_authn_ex"}
    ]
  end
end
