# WebAuthnEx

WebAuthn library for Elixir inspired by [https://github.com/cedarcode/webauthn-ruby](https://github.com/cedarcode/webauthn-ruby)

[![Build Status](https://travis-ci.org/sandergroen/web_authn_ex.svg?branch=master)](https://travis-ci.org/sandergroen/web_authn_ex)

# What is WebAuthn?

- [WebAuthn article with Google IO 2018 talk](https://developers.google.com/web/updates/2018/05/webauthn)
- [Web Authentication API draft article by Mozilla](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [WebAuthn W3C Candidate Recommendation](https://www.w3.org/TR/webauthn/)
- [WebAuthn W3C Editor's Draft](https://w3c.github.io/webauthn/)

## Prerequisites

This package will help your Elixir server act as a conforming [_Relying-Party_](https://www.w3.org/TR/webauthn/#relying-party), in WebAuthn terminology. But for the [_Registration_](https://www.w3.org/TR/webauthn/#registration) and [_Authentication_](https://www.w3.org/TR/webauthn/#authentication) ceremonies to work, you will also need

### A conforming User Agent

Currently supporting [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API):
  - [Mozilla Firefox](https://www.mozilla.org/firefox/) 60+
  - [Google Chrome](https://www.google.com/chrome/) 67+
  - [Google Chrome for Android](https://play.google.com/store/apps/details?id=com.android.chrome) 70+

### A conforming Authenticator

* Roaming authenticators
  * [Security Key by Yubico](https://www.yubico.com/product/security-key-by-yubico/)
  * [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/) key
* Platform authenticators
  * Android's Fingerprint Scanner
  * MacBook [Touch ID](https://en.wikipedia.org/wiki/Touch_ID)

NOTE: Firefox states ([Firefox 60 release notes](https://www.mozilla.org/en-US/firefox/60.0/releasenotes/)) they only support USB FIDO2 or FIDO U2F enabled devices in their current implementation (version 60).
  It's up to the gem's user to verify user agent compatibility if any other device wants to be used as the authenticator component.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `web_authn_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:web_authn_ex, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/web_authn_ex](https://hexdocs.pm/web_authn_ex).

# Usage

NOTE: You can find a working example on how to use this package in a Phoenix app in [https://github.com/sandergroen/webauthn_phoenix_demo](https://github.com/sandergroen/webauthn_phoenix_demo)

# Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/sandergroen/web_authn_ex](https://github.com/sandergroen/web_authn_ex).

