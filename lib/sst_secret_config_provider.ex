defmodule SSTSecretConfigProvider do
  @moduledoc """
  Config Provider that loads the SST secrets from an encrypted file
  and merges them into the Config.

  ## Usage

      []

  ## Options

   - `:sst_key` - The decryption key. If it is not provided, then the `SST_KEY`
     environment variable is checked.

   - `:sst_key_file` - The file with encrypted secret data. If it is not
     provided, then the `SST_KEY_FILE` environment variable is checked.

   - `:sst_key_file_data` - You can pass the encrypted data directly as a
     base64-encoded string if you prefer. Does not check an environment
     variable.

  """

  @behaviour Config.Provider

  @impl Config.Provider
  def init(opts) do
    Keyword.validate!(opts, [:sst_key, :sst_key_file, :sst_key_file_data])

    key = fetch_opt(opts, :sst_key, "SST_KEY") |> Base.decode64!()

    encrypted_data =
      case Keyword.get(opts, :sst_key_file_data) do
        nil -> fetch_opt(opts, :sst_key_file, "SST_KEY_FILE") |> File.read!()
        data -> Base.decode64!(data)
      end

    encrypted_data
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

  defp fetch_opt(opts, key, env_key) do
    with nil <- Keyword.get(opts, key),
         nil <- System.get_env(env_key) do
      raise ArgumentError, message: "#{key} option or #{env_key} env var is required"
    end
  end
end
