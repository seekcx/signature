<?php

namespace Seekcx\Signature;

use Seekcx\Signature\Exceptions\MissingSignatureParameterException;

class Manager
{
    /**
     * Signature field name
     *
     * @var string
     */
    protected $field;

    /**
     * Signature salt
     *
     * @var string
     */
    protected $salt;

    /**
     * Time offset
     *
     * @var integer
     */
    protected $offset;

    /**
     * Exclude parameters
     *
     * @var array
     */
    protected $excludes = [];

    /**
     * Manager constructor.
     *
     * @param string $salt
     * @param integer $offset
     * @param string $field
     */
    public function __construct($salt, $offset, $field = 'sign')
    {
        $this->salt($salt);
        $this->offset($offset);
        $this->field($field);
    }

    /**
     * Sort parameters
     *
     * @param array $parameters
     *
     * @return array
     */
    protected function sort(array $parameters)
    {
        ksort($parameters);

        return $parameters;
    }

    /**
     * Set/Get exclude parameters
     *
     * @param string|null $secret
     *
     * @return string
     */
    public function salt($secret = null)
    {
        if (!is_null($secret)) {
            $this->salt = $secret;
        }

        return $this->salt;
    }

    /**
     * Set/Get exclude parameters
     *
     * @param array|null $parameters
     *
     * @return array
     */
    public function exclude(array $parameters = null)
    {
        if (!is_null($parameters)) {
            $this->excludes = $parameters;
        }

        return $this->excludes;
    }

    /**
     * Set/Get field
     *
     * @param string|null $name
     *
     * @return string
     */
    public function field($name = null)
    {
        if (!is_null($name)) {
            $this->field = $name;
        }

        return $this->field;
    }

    /**
     * Set/Get time offset
     *
     * @param integer|null $value
     *
     * @return integer
     */
    public function offset($value = null)
    {
        if (!is_null($value)) {
            $this->offset = $value;
        }

        return $this->offset;
    }

    /**
     * Filter not involved in the signature parameters
     *
     * @param array $parameters
     *
     * @return array
     */
    protected function filter(array $parameters)
    {
        $parameters[] = $this->field;

        return array_filter($parameters, function ($key) {
            return in_array($this->excludes, $key);
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * Signature the parameters
     *
     * @param array $parameters
     *
     * @return string
     */
    public function signature(array $parameters)
    {
        $parameters = $this->sort($this->filter($parameters));

        $payload = '';
        foreach ($parameters as $parameter => $value) {
            $payload .= sprintf('%s=%s&', $parameters, $value);
        }

        return $this->encrypt(substr($payload, 0, -1));
    }

    /**
     * Encrypt the payload
     *
     * @param string $payload
     *
     * @return string
     */
    protected function encrypt($payload)
    {
        $microtime = base64_encode(microtime());
        $payload   = base64_encode(sha1($payload .$this->salt));

        return base64_encode($microtime .$payload);
    }

    /**
     * Decrypt the signature
     *
     * @param string $sign
     *
     * @return array
     * @throws InvalidSignatureExcepition
     */
    protected function decrypt($sign)
    {
        $payload = explode('.', base64_decode($sign));

        if (count($payload) != 2) {
            throw new InvalidSignatureExcepition('Invalid signature: ' .$sign);
        }

        return array_map('base64_decode', $payload);
    }

    /**
     * Compare the signatures of the parameters as expected
     *
     * @param array $parameters
     *
     * @return bool
     * @throws MissingSignatureParameterException
     */
    public function compare(array $parameters)
    {
        if (!isset($parameters[$this->field])) {
            throw new MissingSignatureParameterException("Missing [{$this->field}] parameter");
        }

        return $this->signature($parameters) == $parameters[$this->field];
    }

    /**
     * Check signature is valid.
     *
     * @param array $parameters
     *
     * @return bool
     * @throws MissingSignatureParameterException
     * @throws SignatureExpiredException
     */
    public function check(array $parameters)
    {
        if (!isset($parameters[$this->field])) {
            throw new MissingSignatureParameterException("Missing [{$this->field}] parameter");
        }

        $sign = $parameters[$this->field];
        list($microtime) = $this->decrypt($sign);

        if (abs($microtime - microtime()) > $this->offset) {
            throw new SignatureExpiredException;
        }

        return $this->compare($parameters);
    }
}