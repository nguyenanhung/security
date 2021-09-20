<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 10/18/18
 * Time: 09:33
 */

namespace nguyenanhung\MySecurity\Helper;

if (!class_exists('nguyenanhung\MySecurity\Helper\Xss')) {
    /**
     * Class Xss
     *
     * Class Xss Security được kế thừa từ class Security của CodeIgniter
     *
     * @package   nguyenanhung\MySecurity\Helper
     * @author    713uk13m <dev@nguyenanhung.com>
     * @copyright 713uk13m <dev@nguyenanhung.com>
     *
     * @see       https://codeigniter.com/userguide3/libraries/security.html
     */
    class Xss
    {
        /**
         * XSS Clean
         *
         * **************************************************************
         * *********** This function and other functions that it uses
         * *********** are taken from Codeigniter 2.1.3 and modified
         * *********** them to our needs. In turn, I have taken this from
         * *********** JasonMortonNZ.
         ***************************************************************
         *
         *
         * Sanitizes data so that Cross Site Scripting Hacks can be
         * prevented.  This function does a fair amount of work but
         * it is extremely thorough, designed to prevent even the
         * most obscure XSS attempts.  Nothing is ever 100% foolproof,
         * of course, but I haven't been able to get anything passed
         * the filter.
         *
         * Note: This function should only be used to deal with data
         * upon submission.  It's not something that should
         * be used for general runtime processing.
         *
         * This function was based in part on some code and ideas I
         * got from Bitflux: http://channel.bitflux.ch/wiki/XSS_Prevention
         *
         * To help develop this script I used this great list of
         * vulnerabilities along with a few other hacks I've
         * harvested from examining vulnerabilities in other programs:
         * http://ha.ckers.org/xss.html
         *
         * @param mixed $str string or array
         * @param bool  $is_image
         *
         * @return    string|array
         */
        public static function xss_clean($str, $is_image = false)
        {
            /*
             * Is the string an array?
             *
             */
            if (is_array($str)) {
                while (list($key) = each($str)) {
                    $str[$key] = self::xss_clean($str[$key]);
                }

                return $str;
            }
            /*
             * Remove Invisible Characters
             */
            $str = self::removeInvisibleCharacters($str);
            // Validate Entities in URLs
            $str = self::validateEntities($str);
            /*
             * URL Decode
             *
             * Just in case stuff like this is submitted:
             *
             * <a href="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">Google</a>
             *
             * Note: Use rawurldecode() so it does not remove plus signs
             *
             */
            $str = rawurldecode($str);
            /*
             * Convert character entities to ASCII
             *
             * This permits our tests below to work reliably.
             * We only convert entities that are within tags since
             * these are the ones that will pose security problems.
             *
             */
            $entitiesRegex = "/[a-z]+=([\'\"]).*?\\1/si";
            $str           = preg_replace_callback($entitiesRegex, function ($match) {
                return str_replace(['>', '<', '\\'], ['&gt;', '&lt;', '\\\\'], $match[0]);
            }, $str);
            $str           = preg_replace_callback("/<\w+.*?(?=>|<|$)/si", 'self::entity_decode', $str);
            /*
             * Remove Invisible Characters Again!
             */
            $str = self::removeInvisibleCharacters($str);
            /*
             * Convert all tabs to spaces
             *
             * This prevents strings like this: ja	vascript
             * NOTE: we deal with spaces between characters later.
             * NOTE: preg_replace was found to be amazingly slow here on
             * large blocks of data, so we use str_replace.
             */
            if (strpos($str, "\t") !== false) {
                $str = str_replace("\t", ' ', $str);
            }
            /*
             * Capture converted string for later comparison
             */
            $converted_string = $str;
            // Remove Strings that are never allowed
            $str = self::doNeverAllowed($str);
            /*
             * Makes PHP tags safe
             *
             * Note: XML tags are inadvertently replaced too:
             *
             * <?xml
             *
             * But it doesn't seem to pose a problem.
             */
            if ($is_image === true) {
                // Images have a tendency to have the PHP short opening and
                // closing tags every so often so we skip those and only
                // do the long opening tags.
                $str = preg_replace('/<\?(php)/i', "&lt;?\\1", $str);
            } else {
                $str = str_replace(['<?', '?' . '>'], ['&lt;?', '?&gt;'], $str);
            }
            /*
             * Compact any exploded words
             *
             * This corrects words like:  j a v a s c r i p t
             * These words are compacted back to their correct state.
             */
            $words = [
                'javascript', 'expression', 'vbscript', 'script', 'base64',
                'applet', 'alert', 'document', 'write', 'cookie', 'window'
            ];
            foreach ($words as $word) {
                $temp = '';
                for ($i = 0, $wordlen = strlen($word); $i < $wordlen; $i++) {
                    $temp .= substr($word, $i, 1) . "\s*";
                }
                // We only want to do this when it is followed by a non-word character
                // That way valid stuff like "dealer to" does not become "dealerto"
                $str = preg_replace_callback('#(' . substr($temp, 0, -3) . ')(\W)#is', function ($matches) {
                    return preg_replace('/\s+/s', '', $matches[1]) . $matches[2];
                }, $str);
            }
            /*
             * Remove disallowed Javascript in links or img tags
             * We used to do some version comparisons and use of stripos for PHP5,
             * but it is dog slow compared to these simplified non-capturing
             * preg_match(), especially if the pattern exists in the string
             */
            do {
                $original = $str;
                if (preg_match("/<a/i", $str)) {
                    $str = preg_replace_callback("#<a\s+([^>]*?)(>|$)#si", function ($match) {
                        $htmlTagPattern = '#href=.*?(alert\(|alert&\#40;|javascript\:|livescript\:|mocha\:|charset\=|window\.|document\.|\.cookie|<script|<xss|data\s*:)#si';

                        return str_replace(
                            $match[1],
                            preg_replace(
                                $htmlTagPattern,
                                '',
                                self::filterAttributes(str_replace(['<', '>'], '', $match[1]))
                            ),
                            $match[0]
                        );
                    }, $str);
                }
                if (preg_match("/<img/i", $str)) {
                    $str = preg_replace_callback("#<img\s+([^>]*?)(\s?/?>|$)#si", function ($match) {
                        $htmlTagPattern = '#src=.*?(alert\(|alert&\#40;|javascript\:|livescript\:|mocha\:|charset\=|window\.|document\.|\.cookie|<script|<xss|base64\s*,)#si';

                        return str_replace(
                            $match[1],
                            preg_replace(
                                $htmlTagPattern,
                                '',
                                self::filterAttributes(str_replace(['<', '>'], '', $match[1]))
                            ),
                            $match[0]
                        );
                    }, $str);
                }
                if (preg_match("/script/i", $str) or preg_match("/xss/i", $str)) {
                    $htmlTagPattern = "#<(/*)(script|xss)(.*?)\>#si";
                    $str            = preg_replace($htmlTagPattern, '[removed]', $str);
                }
            }
            while ($original != $str);
            unset($original);
            // Remove evil attributes such as style, onclick and xmlns
            $str = self::removeEvilAttributes($str, $is_image);
            /*
             * Sanitize naughty HTML elements
             *
             * If a tag containing any of the words in the list
             * below is found, the tag gets converted to entities.
             *
             * So this: <blink>
             * Becomes: &lt;blink&gt;
             */
            $naughty = 'alert|applet|audio|basefont|base|behavior|bgsound|blink|body|embed|expression|form|frameset|frame|head|html|ilayer|iframe|input|isindex|layer|link|meta|object|plaintext|style|script|textarea|title|video|xml|xss';
            $str     = preg_replace_callback('#<(/*\s*)(' . $naughty . ')([^><]*)([><]*)#is', function ($matches) {
                // encode opening brace
                $str = '&lt;' . $matches[1] . $matches[2] . $matches[3];

                // encode captured opening or closing brace to prevent recursive vectors
                $str .= str_replace(['>', '<'], ['&gt;', '&lt;'], $matches[4]);

                return $str;
            }, $str);
            /*
             * Sanitize naughty scripting elements
             *
             * Similar to above, only instead of looking for
             * tags it looks for PHP and JavaScript commands
             * that are disallowed.  Rather than removing the
             * code, it simply converts the parenthesis to entities
             * rendering the code un-executable.
             *
             * For example:	eval('some code')
             * Becomes:		eval&#40;'some code'&#41;
             */
            $str = preg_replace('#(alert|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)\((.*?)\)#si', "\\1\\2&#40;\\3&#41;", $str);
            // Final clean up
            // This adds a bit of extra precaution in case
            // something got through the above filters
            $str = self::doNeverAllowed($str);
            /*
             * Images are Handled in a Special Way
             * - Essentially, we want to know that after all of the character
             * conversion is done whether any unwanted, likely XSS, code was found.
             * If not, we return TRUE, as the image is clean.
             * However, if the string post-conversion does not matched the
             * string post-removal of XSS, then it fails, as there was unwanted XSS
             * code found and removed/changed during processing.
             */
            if ($is_image === true) {
                if (($str == $converted_string)) {
                    return true;
                }

                return false;
            }

            return $str;
        }//xss_clean

        /**
         * Function remove_invisible_characters
         *
         * @author: 713uk13m <dev@nguyenanhung.com>
         * @time  : 2018-12-03 15:50
         *
         * @param      $str
         * @param bool $url_encoded
         *
         * @return string|string[]|null
         */
        protected static function removeInvisibleCharacters($str, bool $url_encoded = true)
        {

            $non_displayables = [];

            // every control character except newline (dec 10)
            // carriage return (dec 13), and horizontal tab (dec 09)

            if ($url_encoded) {
                $non_displayables[] = '/%0[0-8bcef]/';    // url encoded 00-08, 11, 12, 14, 15
                $non_displayables[] = '/%1[0-9a-f]/';    // url encoded 16-31
            }

            $non_displayables[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';    // 00-08, 11, 12, 14-31, 127
            do {
                $str = preg_replace($non_displayables, '', $str, -1, $count);
            }
            while ($count);

            return $str;
        }//remove_invisible_characters

        /**
         * Validate URL entities
         *
         * Called by xss_clean()
         *
         * @param string
         *
         * @return    string
         */
        protected static function validateEntities($str): string
        {
            /*
             * Protect GET variables in URLs
             */
            $xss_hash        = md5(time() + mt_rand(0, 1999999999));
            $entitiesPattern = '|\&([a-z\_0-9\-]+)\=([a-z\_0-9\-]+)|i';
            $str             = preg_replace($entitiesPattern, $xss_hash . "\\1=\\2", $str);
            /*
             * Validate standard character entities
             *
             * Add a semicolon if missing.  We do this to enable
             * the conversion of entities to ASCII later.
             *
             */
            $str = preg_replace('#(&\#?[0-9a-z]{2,})([\x00-\x20])*;?#i', "\\1;\\2", $str);
            /*
             * Validate UTF16 two byte encoding (x00)
             *
             * Just as above, adds a semicolon if missing.
             *
             */
            $str = preg_replace('#(&\#x?)([0-9A-F]+);?#i', "\\1\\2;", $str);

            /*
             * Un-Protect GET variables in URLs
             */

            return str_replace($xss_hash, '&', $str);
        }//validate_entities

        /**
         * Do Never Allowed
         *
         * A utility function for xss_clean()
         *
         * @param string
         *
         * @return    string
         */
        protected static function doNeverAllowed($str): string
        {
            /**
             * List of never allowed strings
             */
            $never_allowed_str = [
                'document.cookie' => '[removed]',
                'document.write'  => '[removed]',
                '.parentNode'     => '[removed]',
                '.innerHTML'      => '[removed]',
                'window.location' => '[removed]',
                '-moz-binding'    => '[removed]',
                '<!--'            => '&lt;!--',
                '-->'             => '--&gt;',
                '<![CDATA['       => '&lt;![CDATA[',
                '<comment>'       => '&lt;comment&gt;'
            ];
            /**
             * List of never allowed regex replacement
             */
            $never_allowed_regex = [
                'javascript\s*:',
                'expression\s*(\(|&\#40;)', // CSS and IE
                'vbscript\s*:', // IE, surprise!
                'Redirect\s+302',
                "([\"'])?data\s*:[^\\1]*?base64[^\\1]*?,[^\\1]*?\\1?"
            ];
            $str                 = str_replace(array_keys($never_allowed_str), $never_allowed_str, $str);
            foreach ($never_allowed_regex as $regex) {
                $str = preg_replace('#' . $regex . '#is', '[removed]', $str);
            }

            return $str;
        }//do_never_allowed

        /**
         * Remove Evil HTML Attributes (like evenhandlers and style)
         *
         * It removes the evil attribute and either:
         *    - Everything up until a space
         *        For example, everything between the pipes:
         *        <a |style=document.write('hello');alert('world');| class=link>
         *    - Everything inside the quotes
         *        For example, everything between the pipes:
         *        <a |style="document.write('hello'); alert('world');"| class="link">
         *
         * @param string  $str      The string to check
         * @param boolean $is_image TRUE if this is an image
         *
         * @return string The string with the evil attributes removed
         */
        protected static function removeEvilAttributes(string $str, bool $is_image): string
        {
            // All javascript event handlers (e.g. onload, onclick, onmouseover), style, and xmlns
            $evil_attributes = ['on\w*', 'style', 'xmlns', 'formaction'];
            if ($is_image === true) {
                /*
                 * Adobe Photoshop puts XML metadata into JFIF images,
                 * including namespacing, so we have to allow this for images.
                 */
                unset($evil_attributes[array_search('xmlns', $evil_attributes)]);
            }
            do {
                $count   = 0;
                $attribs = [];
                // find occurrences of illegal attribute strings without quotes
                preg_match_all('/(' . implode('|', $evil_attributes) . ')\s*=\s*([^\s>]*)/is', $str, $matches, PREG_SET_ORDER);
                foreach ($matches as $attr) {
                    $attribs[] = preg_quote($attr[0], '/');
                }
                // find occurrences of illegal attribute strings with quotes (042 and 047 are octal quotes)
                $regexPattern = "/(" . implode('|', $evil_attributes) . ")\s*=\s*(\042|\047)([^\\2]*?)(\\2)/is";
                preg_match_all($regexPattern, $str, $matches, PREG_SET_ORDER);
                foreach ($matches as $attr) {
                    $attribs[] = preg_quote($attr[0], '/');
                }
                // replace illegal attribute strings that are inside an html tag
                if (count($attribs) > 0) {
                    $str = preg_replace("/<(\/?[^><]+?)([^A-Za-z<>\-])(.*?)(" . implode('|', $attribs) . ")(.*?)([\s><])([><]*)/i", '<$1 $3$5$6$7', $str, -1, $count);
                }
            }
            while ($count);

            return $str;
        }//remove_evil_attributes

        /**
         * HTML Entities Decode
         *
         * This function is a replacement for html_entity_decode()
         *
         * The reason we are not using html_entity_decode() by itself is because
         * while it is not technically correct to leave out the semicolon
         * at the end of an entity most browsers will still interpret the entity
         * correctly.  html_entity_decode() does not convert entities without
         * semicolons, so we are left with our own little solution here. Bummer.
         *
         * @param string
         * @param string
         *
         * @return    string
         */
        protected static function entityDecode($arr, $charset = 'UTF-8'): string
        {
            $str = $arr[0];
            if (stristr($str, '&') === false) {
                return $str;
            }
            $str = html_entity_decode($str, ENT_COMPAT, $charset);
            $str = preg_replace_callback('~&#x(0*[0-9a-f]{2,5})~i', create_function('$matches', 'return chr(hexdec($matches[1]));'), $str);

            return preg_replace_callback('~&#([0-9]{2,4})~', create_function('$matches', 'return chr($matches[1]);'), $str);
        }//entity_decode

        /**
         * Filter Attributes
         *
         * Filters tag attributes for consistency and safety
         *
         * @param string
         *
         * @return    string
         */
        protected static function filterAttributes($str): string
        {
            $out          = '';
            $regexPattern = '#\s*[a-z\-]+\s*=\s*(\042|\047)([^\\1]*?)\\1#is';
            if (preg_match_all($regexPattern, $str, $matches)) {
                foreach ($matches[0] as $match) {
                    $out .= preg_replace("#/\*.*?\*/#s", '', $match);
                }
            }

            return $out;
        }//filter_attributes
    }
}
