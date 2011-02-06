<?php
/**
 * Crypt Component
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled with this
 * package in the file LICENSE. It is also available through the world-wide-web
 * at this URL: http://www.opensource.org/licenses/bsd-license
 *
 * @category   Components
 * @package    CakePHP
 * @subpackage PHP
 * @copyright  Copyright (c) 2011 Signified (http://signified.com.au)
 * @license    http://www.opensource.org/licenses/bsd-license    New BSD License
 * @version    1.0
 */

/**
 * CryptComponent class
 *
 * This component is used for encrypting/decrypting data
 *
 * @category   Components
 * @package    CakePHP
 * @subpackage PHP
 * @copyright  Copyright (c) 2011 Signified (http://signified.com.au)
 * @license    http://www.opensource.org/licenses/bsd-license    New BSD License
 */
class CryptComponent extends Object
{
    /**
     * Instance of the MCRYPT module
     *
     * @var object
     * @access protected
     */
    protected $_mcrypt = null;

    /**
     * Initialise MCRYPT module
     *
     * @return object $this
     * @access protected
     */
    protected function _mcryptInit()
    {
        $this->mcrypt = mcrypt_module_open('tripledes', '', 'ecb', '');
        $ivSize = mcrypt_enc_get_iv_size($this->mcrypt);
        $key = substr(sha1(Configure::read('Security.cipher_seed')), 0, $ivSize);
        $iv = mcrypt_create_iv($ivSize, MCRYPT_RAND);
        mcrypt_generic_init($this->mcrypt, $key, $iv);
        return $this;
    }

    /**
     * Decrypt data
     *
     * @param string $data The data to be decrypted
     * @return string Returns the decrypted string or false
     * @access public
     */
    public function decrypt($data = null)
    {
        if (!is_null($data)) {
            $data = (string) urldecode(base64_decode(trim($data)));
            $this->_mcryptInit();
            $decrypted = trim(mdecrypt_generic($this->mcrypt, $data));
            if (!mcrypt_generic_deinit($this->mcrypt) || !mcrypt_module_close($this->mcrypt)) {
                return false;
            }
            return $decrypted;
        } else {
            return false;
        }
    }

    /**
     * Encrypt data
     *
     * @param string $data The data to be encrypted
     * @return string Returns the encrypted string or false
     * @access public
     */
    public function encrypt($data = null)
    {
        if (!is_null($data)) {
            $data = (string) $data;
            $this->_mcryptInit();
            $encrypted = base64_encode(urlencode(mcrypt_generic($this->mcrypt, $data)));
            if (!mcrypt_generic_deinit($this->mcrypt) || !mcrypt_module_close($this->mcrypt)) {
                return false;
            }
            return $encrypted;
        } else {
            return false;
        }
    }
}