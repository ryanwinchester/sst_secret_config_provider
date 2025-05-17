defmodule SSTSecretConfigProvider do
  @moduledoc """
  Config Provider that loads the SST secrets from an encrypted file
  and merges them into the Config.
  """

  @behaviour Config.Provider

  @impl Config.Provider
  def init(opts) do
    key = Keyword.fetch!(opts, :key) |> Base.decode64!()

    opts
    |> Keyword.fetch!(:key_file)
    |> File.read!()
    |> decode_keyfile(key)
    |> JSON.decode!()
  end

  @impl Config.Provider
  def load(config, _secrets) do
    # TODO: Walk the config and replace secrets.
    Config.Reader.merge(config, [])
  end

  @doc """
  Decode the encrypted data that was stored in the keyfile, using the key.
  """
  def decode_keyfile(encrypted_data, key) do
    cipher_size = byte_size(encrypted_data) - 16

    <<ciphertext::binary-size(cipher_size), auth_tag::binary-16>> = encrypted_data

    # 12 zero bytes nonce.
    iv = <<0::96>>
    # There is no additional auth data.
    aad = <<>>

    :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, auth_tag, false)
  end
end
