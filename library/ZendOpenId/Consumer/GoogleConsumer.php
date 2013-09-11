<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_OpenId
 */

namespace ZendOpenId\Consumer;

use Zend\Http\Response;
use ZendOpenId\OpenId;
use ZendOpenId\Extension;
use Zend\Session\Container as SessionContainer;

use ZendOpenId\Consumer\GenericConsumer;

/**
 * OpenID consumer implementation for Google Federated Login
 * Based on patches suggested at http://framework.zend.com/issues/browse/ZF-6905
 *
 * @category   Zend
 * @package    Zend_OpenId
 * @subpackage Zend_OpenId_Consumer
 */
class GoogleConsumer extends GenericConsumer
{
    const OPENID_SPEC_2_0 = 'http://specs.openid.net/auth/2.0/identifier_select';

    /**
     * Performs discovery of identity and finds OpenID URL, OpenID server URL
     * and OpenID protocol version. Returns true on succees and false on
     * failure.
     *
     * @param string &$id OpenID identity URL
     * @param string &$server OpenID server URL
     * @param float &$version OpenID protocol version
     * @return bool
     * @todo OpenID 2.0 (7.3) XRI and Yadis discovery
     */
    protected function _discovery(&$id, &$server, &$version)
    {
        $realId = $id;
        if ($this->_storage->getDiscoveryInfo(
            $id,
            $realId,
            $server,
            $version,
            $expire
        )) {
            $id = $realId;
            return true;
        }

        /* TODO: OpenID 2.0 (7.3) XRI and Yadis discovery */

        /* HTML-based discovery */
        $response = $this->_httpRequest($id, 'GET', array(), $status);
        if ($status != 200 || !is_string($response)) {
            return false;
        }
        if (preg_match('/([^>]+)<\/URI>/i', $response, $r)) {
            $version = 2.0;
            $server = $r[1];
        } else {
            return false;
        }
        if ($version >= 2.0) {
            if (preg_match(
                '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.local_id[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                $response,
                $r
            )) {
                $realId = $r[3];
            } elseif (preg_match(
                '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid2.local_id[ \t]*[^"\']*\\3[^>]*\/?>/i',
                $response,
                $r
            )) {
                $realId = $r[2];
            }
        } else {
            if (preg_match(
                '/<link[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.delegate[ \t]*[^"\']*\\1[^>]*href=(["\'])([^"\']+)\\2[^>]*\/?>/i',
                $response,
                $r
            )) {
                $realId = $r[3];
            } elseif (preg_match(
                '/<link[^>]*href=(["\'])([^"\']+)\\1[^>]*rel=(["\'])[ \t]*(?:[^ \t"\']+[ \t]+)*?openid.delegate[ \t]*[^"\']*\\3[^>]*\/?>/i',
                $response,
                $r
            )) {
                $realId = $r[2];
            }
        }

        $expire = time() + 60 * 60;
        $this->_storage->addDiscoveryInfo($id, $realId, $server, $version, $expire);
        $id = $realId;
        return true;
    }

    /**
     * Performs check of OpenID identity.
     *
     * This is the first step of OpenID authentication process.
     * On success the function does not return (it does HTTP redirection to
     * server and exits). On failure it returns false.
     *
     * @param bool $immediate enables or disables interaction with user
     * @param string $id OpenID identity
     * @param string $returnTo HTTP URL to redirect response from server to
     * @param string $root HTTP URL to identify consumer on server
     * @param mixed $extensions extension object or array of extensions objects
     * @param Response $response an optional response object to perform HTTP or HTML form redirection
     * @return bool
     */
    protected function _checkId(
        $immediate,
        $id,
        $returnTo = null,
        $root = null,
        $extensions = null,
        Response $response = null
    ) {
        $this->_setError('');

        if (!OpenId::normalize($id)) {
            $this->_setError("Normalisation failed");
            return false;
        }
        $claimedId = $id;

        if (!$this->_discovery($id, $server, $version)) {
            $this->_setError("Discovery failed: " . $this->getError());
            return false;
        }
        if (!$this->_associate($server, $version)) {
            $this->_setError("Association failed: " . $this->getError());
            return false;
        }

        if (!$this->_getAssociation(
            $server,
            $handle,
            $macFunc,
            $secret,
            $expires
        )) {
            /* Use dumb mode */
            unset($handle);
            unset($macFunc);
            unset($secret);
            unset($expires);
        }

        $params = array();
        if ($version >= 2.0) {
            $params['openid.ns'] = OpenId::NS_2_0;
        }

        $params['openid.mode'] = $immediate ?
            'checkid_immediate' : 'checkid_setup';

        $params['openid.identity'] = self::OPENID_SPEC_2_0;
        $params['openid.claimed_id'] = self::OPENID_SPEC_2_0;

        if ($version <= 2.0) {
            if ($this->_session !== null) {
                $this->_session->identity = self::OPENID_SPEC_2_0;
                $this->_session->claimed_id = self::OPENID_SPEC_2_0;

            } elseif (defined('SID')) {
                $_SESSION["zend_openid"] = array(
                    "identity" => self::OPENID_SPEC_2_0,
                    "claimed_id" => self::OPENID_SPEC_2_0);
            } elseif (!headers_sent()) {
                $this->_session = new SessionContainer("zend_openid");
                $this->_session->identity = self::OPENID_SPEC_2_0;
                $this->_session->claimed_id = self::OPENID_SPEC_2_0;
            }
        }

        if (isset($handle)) {
            $params['openid.assoc_handle'] = $handle;
        }

        $params['openid.return_to'] = OpenId::absoluteUrl($returnTo);

        if (empty($root)) {
            $root = OpenId::selfUrl();
            if ($root[strlen($root)-1] != '/') {
                $root = dirname($root);
            }
        }
        if ($version >= 2.0) {
            $params['openid.realm'] = $root;
        } else {
            $params['openid.trust_root'] = $root;
        }

        if (!Extension\AbstractExtension::forAll($extensions, 'prepareRequest', $params)) {
            $this->_setError("Extension::prepareRequest failure");
            return false;
        }

        OpenId::redirect($server, $params, $response);
        return true;
    }
}
