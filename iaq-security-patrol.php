<?php
/**
 * Plugin Name: IAQ Security Patrol
 * Description: Lightweight WordPress defense against exploit probes, abusive scraping patterns, and temporary IP abuse.
 * Version: 0.4.1
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: IAQ
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: iaq-security-patrol
 */

if (!defined('ABSPATH')) exit;

final class IAQ_Security_Patrol {
    const MENU_SLUG = 'iaq-security-patrol';
    const OPTION_SETTINGS = 'iaq_security_patrol_settings';
    const TABLE_EVENTS = 'iaq_security_patrol_events';
    const TABLE_BANS = 'iaq_security_patrol_bans';
    const VERIFIED_BOT_CACHE_TTL = 43200;

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action('init', [$this, 'maybe_block_request'], 0);
        add_action('template_redirect', [$this, 'inspect_behavior'], 1);
        add_action('template_redirect', [$this, 'inspect_request'], 999);
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_post_iaq_security_unban', [$this, 'handle_unban']);
        add_action('admin_post_iaq_security_clear_events', [$this, 'handle_clear_events']);
        add_action('admin_init', [$this, 'maybe_create_tables']);
        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
    }

    public static function activate() {
        self::create_tables();
        if (!get_option(self::OPTION_SETTINGS)) {
            add_option(self::OPTION_SETTINGS, [
                'enabled' => 1,
                'threshold_404' => 10,
                'window_minutes' => 10,
                'ban_hours' => 24,
                'php_only_mode' => 1,
                'burst_hits' => 12,
                'burst_seconds' => 60,
                'sustained_hits' => 35,
                'sustained_minutes' => 10,
                'direct_hits' => 18,
                'direct_minutes' => 3,
            ]);
        }
    }

    private static function table_name($suffix) {
        global $wpdb;
        return $wpdb->prefix . $suffix;
    }

    public static function create_tables() {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $events = self::table_name(self::TABLE_EVENTS);
        $bans = self::table_name(self::TABLE_BANS);
        $charset = $wpdb->get_charset_collate();

        dbDelta("CREATE TABLE {$events} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(64) NOT NULL,
            user_agent TEXT NULL,
            method VARCHAR(12) DEFAULT '',
            uri TEXT NOT NULL,
            reason VARCHAR(120) DEFAULT '',
            risk INT DEFAULT 0,
            status_code INT DEFAULT 0,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY ip_created (ip, created_at),
            KEY reason_created (reason, created_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$bans} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(64) NOT NULL,
            reason VARCHAR(255) DEFAULT '',
            risk INT DEFAULT 0,
            banned_until DATETIME NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip (ip),
            KEY banned_until (banned_until)
        ) {$charset};");
    }

    public function maybe_create_tables() {
        if (!current_user_can('manage_options')) return;
        global $wpdb;
        $events = self::table_name(self::TABLE_EVENTS);
        $exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $events));
        if ($exists !== $events) self::create_tables();
    }

    private function settings() {
        $defaults = [
            'enabled' => 1,
            'threshold_404' => 10,
            'window_minutes' => 10,
            'ban_hours' => 24,
            'php_only_mode' => 1,
            'burst_hits' => 12,
            'burst_seconds' => 60,
            'sustained_hits' => 35,
            'sustained_minutes' => 10,
            'direct_hits' => 18,
            'direct_minutes' => 3,
        ];
        $saved = get_option(self::OPTION_SETTINGS, []);
        return array_merge($defaults, is_array($saved) ? $saved : []);
    }

    private function get_ip() {
        $remote = $this->remote_ip();

        // CF-Connecting-IP is trustworthy only when the TCP peer is Cloudflare.
        // Never accept forwarded IP headers directly from arbitrary visitors.
        if ($this->is_cloudflare_ip($remote) && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $candidate = trim(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])));
            if (filter_var($candidate, FILTER_VALIDATE_IP)) return $candidate;
        }

        if ($remote !== '0.0.0.0') return $remote;
        return '0.0.0.0';
    }

    private function remote_ip() {
        if (empty($_SERVER['REMOTE_ADDR'])) return '0.0.0.0';
        $remote = trim(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])));
        return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
    }

    private function cloudflare_ranges() {
        return [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
            '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];
    }

    private function is_cloudflare_ip($ip) {
        return $this->ip_in_ranges($ip, $this->cloudflare_ranges());
    }

    private function ip_in_ranges($ip, $ranges) {
        foreach ((array) $ranges as $range) {
            if ($this->ip_in_cidr($ip, $range)) return true;
        }
        return false;
    }

    private function ip_in_cidr($ip, $cidr) {
        if (!filter_var($ip, FILTER_VALIDATE_IP) || strpos($cidr, '/') === false) return false;
        list($network, $prefix) = explode('/', $cidr, 2);
        $ip_bin = @inet_pton($ip);
        $network_bin = @inet_pton($network);
        if ($ip_bin === false || $network_bin === false || strlen($ip_bin) !== strlen($network_bin)) return false;

        $prefix = (int) $prefix;
        $max_bits = strlen($ip_bin) * 8;
        if ($prefix < 0 || $prefix > $max_bits) return false;

        $whole_bytes = intdiv($prefix, 8);
        $remaining_bits = $prefix % 8;
        if ($whole_bytes > 0 && substr($ip_bin, 0, $whole_bytes) !== substr($network_bin, 0, $whole_bytes)) return false;
        if ($remaining_bits === 0) return true;

        $mask = (0xFF << (8 - $remaining_bits)) & 0xFF;
        return (ord($ip_bin[$whole_bytes]) & $mask) === (ord($network_bin[$whole_bytes]) & $mask);
    }

    private function request_uri() {
        return isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
    }

    private function user_agent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_textarea_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
    }

    private function method() {
        return isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : '';
    }

    private function is_admin_safe_ip() {
        return is_user_logged_in() && current_user_can('manage_options');
    }

    private function is_trusted_request() {
        if ($this->is_admin_safe_ip()) return true;

        // Protect the Cloudflare transport itself if the real-client header is
        // ever absent or malformed. Valid proxied requests are evaluated by
        // their resolved visitor IP, not by the Cloudflare edge IP.
        $remote = $this->remote_ip();
        if ($this->is_cloudflare_ip($remote) && $this->get_ip() === $remote) return true;

        return $this->verified_bot_family() !== '';
    }

    private function verified_bot_family() {
        $ua = $this->user_agent();
        $family = $this->agent_family($ua);
        if ($family === '') return '';

        $ip = $this->get_ip();
        $cache_key = 'iaq_sp_verified_' . md5($family . '|' . $ip);
        $cached = get_transient($cache_key);
        if ($cached === 'yes') return $family;
        if ($cached === 'no') return '';

        $verified = false;
        $dns_suffixes = [
            'googlebot' => ['.googlebot.com', '.google.com', '.googleusercontent.com'],
            'bingbot' => ['.search.msn.com'],
            'yandexbot' => ['.yandex.ru', '.yandex.net', '.yandex.com'],
            'applebot' => ['.applebot.apple.com'],
        ];

        if (isset($dns_suffixes[$family])) {
            $verified = $this->verify_forward_confirmed_reverse_dns($ip, $dns_suffixes[$family]);
        } else {
            $feed = $this->bot_ip_feed($family);
            if ($feed !== '') $verified = $this->ip_in_ranges($ip, $this->remote_ip_ranges($feed));
        }

        set_transient($cache_key, $verified ? 'yes' : 'no', self::VERIFIED_BOT_CACHE_TTL);
        return $verified ? $family : '';
    }

    private function verify_forward_confirmed_reverse_dns($ip, $allowed_suffixes) {
        $host = strtolower(rtrim((string) @gethostbyaddr($ip), '.'));
        if ($host === '' || $host === strtolower($ip)) return false;

        $suffix_ok = false;
        foreach ($allowed_suffixes as $suffix) {
            $suffix = strtolower($suffix);
            if (strlen($host) > strlen($suffix) && substr($host, -strlen($suffix)) === $suffix) {
                $suffix_ok = true;
                break;
            }
        }
        if (!$suffix_ok) return false;

        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        foreach ((array) $records as $record) {
            if (!empty($record['ip']) && $record['ip'] === $ip) return true;
            if (!empty($record['ipv6']) && $record['ipv6'] === $ip) return true;
        }
        return false;
    }

    private function bot_ip_feed($family) {
        $feeds = [
            'oai-searchbot' => 'https://openai.com/searchbot.json',
            'gptbot' => 'https://openai.com/gptbot.json',
            'chatgpt-user' => 'https://openai.com/chatgpt-user.json',
            'perplexitybot' => 'https://www.perplexity.ai/perplexitybot.json',
            'perplexity-user' => 'https://www.perplexity.ai/perplexity-user.json',
        ];
        return isset($feeds[$family]) ? $feeds[$family] : '';
    }

    private function remote_ip_ranges($url) {
        $cache_key = 'iaq_sp_ranges_' . md5($url);
        $cached = get_transient($cache_key);
        if (is_array($cached)) return $cached;

        $response = wp_safe_remote_get($url, [
            'timeout' => 4,
            'redirection' => 2,
            'user-agent' => 'IAQ-Security-Patrol/0.4.1',
        ]);
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) return [];

        $data = json_decode(wp_remote_retrieve_body($response), true);
        $ranges = [];
        foreach ((array) ($data['prefixes'] ?? []) as $entry) {
            $cidr = $entry['ipv4Prefix'] ?? ($entry['ipv6Prefix'] ?? '');
            if (is_string($cidr) && strpos($cidr, '/') !== false) $ranges[] = $cidr;
        }
        if ($ranges) set_transient($cache_key, array_values(array_unique($ranges)), DAY_IN_SECONDS);
        return $ranges;
    }

    private function deny_request() {
        status_header(403);
        nocache_headers();
        header('Content-Type: text/plain; charset=utf-8');
        echo "IAQ Security Patrol: request blocked temporarily.\n";
        exit;
    }

    public function maybe_block_request() {
        $settings = $this->settings();
        if (empty($settings['enabled'])) return;
        if ($this->is_trusted_request()) return;

        global $wpdb;
        $ip = $this->get_ip();
        $bans = self::table_name(self::TABLE_BANS);
        $ban = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$bans} WHERE ip = %s AND banned_until > %s LIMIT 1",
            $ip,
            current_time('mysql')
        ));

        if ($ban) {
            $this->deny_request();
        }
    }

    /**
     * Detect non-human navigation on successful front-end requests.
     * Uses a short-lived transient per IP, so no permanent page-view table is
     * created and normal traffic adds at most one small expiring record per IP.
     */
    public function inspect_behavior() {
        $settings = $this->settings();
        if (empty($settings['enabled']) || $this->is_trusted_request()) return;
        if (!$this->is_behavior_request()) return;

        $ip = $this->get_ip();
        if ($ip === '0.0.0.0') return;

        $now = time();
        $uri = $this->request_uri();
        $ua = $this->user_agent();
        $key = 'iaq_sp_b_' . md5($ip);
        $state = get_transient($key);
        if (!is_array($state)) $state = ['hits' => [], 'direct' => [], 'agents' => []];

        $ten_minutes_ago = $now - (max(1, (int) $settings['sustained_minutes']) * MINUTE_IN_SECONDS);
        $state['hits'] = $this->prune_behavior_items(isset($state['hits']) ? $state['hits'] : [], $ten_minutes_ago);
        $state['direct'] = $this->prune_behavior_items(isset($state['direct']) ? $state['direct'] : [], $ten_minutes_ago);
        $state['agents'] = $this->prune_behavior_items(isset($state['agents']) ? $state['agents'] : [], $ten_minutes_ago);

        $state['hits'][] = ['t' => $now, 'v' => md5($uri)];
        if ($this->is_direct_request()) $state['direct'][] = ['t' => $now, 'v' => md5($uri)];

        $agent_family = $this->verified_bot_family();
        if ($agent_family !== '') $state['agents'][] = ['t' => $now, 'v' => $agent_family];

        set_transient($key, $state, 11 * MINUTE_IN_SECONDS);

        // One IP presenting three or more crawler identities is a layer probe,
        // even when every individual User-Agent looks legitimate.
        if (count(array_unique(wp_list_pluck($state['agents'], 'v'))) >= 3) {
            $this->behavior_ban('user_agent_rotation', 90, count($state['agents']));
            delete_transient($key);
            $this->deny_request();
        }

        // Keep named legitimate crawlers out of volume rules. Identity rotation
        // is evaluated above, so the observed multi-bot spoof remains blocked.
        if ($agent_family !== '') return;

        $burst_since = $now - max(10, (int) $settings['burst_seconds']);
        $burst = $this->count_since($state['hits'], $burst_since);
        if ($burst >= max(5, (int) $settings['burst_hits'])) {
            $this->behavior_ban('rapid_page_burst', 70, $burst);
            delete_transient($key);
            $this->deny_request();
        }

        $sustained = count($state['hits']);
        if ($sustained >= max(15, (int) $settings['sustained_hits'])) {
            $this->behavior_ban('sustained_scraping', 80, $sustained);
            delete_transient($key);
            $this->deny_request();
        }

        $direct_since = $now - (max(1, (int) $settings['direct_minutes']) * MINUTE_IN_SECONDS);
        $direct_items = array_values(array_filter($state['direct'], function ($item) use ($direct_since) {
            return isset($item['t']) && (int) $item['t'] >= $direct_since;
        }));
        $direct_distinct = count(array_unique(wp_list_pluck($direct_items, 'v')));
        if ($direct_distinct >= max(10, (int) $settings['direct_hits'])) {
            $this->behavior_ban('direct_url_enumeration', 85, $direct_distinct);
            delete_transient($key);
            $this->deny_request();
        }
    }

    private function is_behavior_request() {
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) return false;
        if (!in_array($this->method(), ['GET', 'HEAD'], true)) return false;
        $uri = $this->request_uri();
        if (preg_match('#^/(wp-admin|wp-login\.php|wp-cron\.php|wp-json)(?:/|\?|$)#i', $uri)) return false;
        if (preg_match('/\.(?:css|js|map|jpe?g|png|gif|webp|avif|svg|ico|woff2?|ttf|otf|mp3|mp4|webm|pdf|zip|xml|json|txt)(?:\?|$)/i', $uri)) return false;
        return true;
    }

    private function is_direct_request() {
        return empty($_SERVER['HTTP_REFERER']);
    }

    private function prune_behavior_items($items, $since) {
        if (!is_array($items)) return [];
        return array_values(array_filter($items, function ($item) use ($since) {
            return is_array($item) && isset($item['t']) && (int) $item['t'] >= $since;
        }));
    }

    private function count_since($items, $since) {
        $count = 0;
        foreach ((array) $items as $item) {
            if (isset($item['t']) && (int) $item['t'] >= $since) $count++;
        }
        return $count;
    }

    private function agent_family($ua) {
        $families = [
            'Googlebot' => 'googlebot', 'bingbot' => 'bingbot', 'YandexBot' => 'yandexbot',
            'DuckDuckBot' => 'duckduckbot', 'Baiduspider' => 'baiduspider', 'Applebot' => 'applebot',
            'GPTBot' => 'gptbot', 'ChatGPT-User' => 'chatgpt-user', 'OAI-SearchBot' => 'oai-searchbot',
            'ClaudeBot' => 'claudebot', 'Claude-Web' => 'claude-web', 'PerplexityBot' => 'perplexitybot',
            'Perplexity-User' => 'perplexity-user', 'Amazonbot' => 'amazonbot', 'CCBot' => 'ccbot',
            'Bytespider' => 'bytespider', 'Google-Extended' => 'google-extended'
        ];
        foreach ($families as $needle => $family) {
            if (stripos($ua, $needle) !== false) return $family;
        }
        return '';
    }

    private function behavior_ban($reason, $risk, $hits) {
        $this->record_event($reason, $risk, 403);
        $this->ban_now('Behavior auto-ban: ' . sanitize_key($reason) . ' / ' . (int) $hits . ' hits', $risk);
    }

    private function ban_now($reason, $risk) {
        global $wpdb;
        $settings = $this->settings();
        $hours = max(1, (int) $settings['ban_hours']);
        $until = date('Y-m-d H:i:s', current_time('timestamp') + ($hours * HOUR_IN_SECONDS));

        $ip = $this->get_ip();
        if ($this->is_trusted_request() || $this->is_cloudflare_ip($ip)) return;

        $wpdb->replace(self::table_name(self::TABLE_BANS), [
            'ip' => $ip,
            'reason' => sanitize_text_field($reason),
            'risk' => (int) $risk,
            'banned_until' => $until,
            'created_at' => current_time('mysql'),
        ], ['%s','%s','%d','%s','%s']);
    }

    public function inspect_request() {
        $settings = $this->settings();
        if (empty($settings['enabled'])) return;
        if ($this->is_trusted_request()) return;
        if (!is_404()) return;

        $uri = $this->request_uri();
        $risk = 1;
        $reason = '404';

        if ($this->is_immediate_exploit_probe($uri)) {
            $risk = 100;
            $reason = 'exploit_probe';
        } elseif ($this->looks_like_exploit($uri)) {
            $risk = 20;
            $reason = 'exploit_scan';
        } elseif (preg_match('/\.php(?:$|\?)/i', $uri)) {
            $risk = 10;
            $reason = 'php_404';
        } elseif (preg_match('/\.(env|git|sql|zip|tar|gz|bak|old|backup)(?:$|\?)/i', $uri)) {
            $risk = 20;
            $reason = 'sensitive_file_probe';
        }

        $this->record_event($reason, $risk, 404);

        if ($reason === 'exploit_probe') {
            $this->ban_now('Exploit probe: ' . $this->probe_label($uri), $risk);
            $this->deny_request();
        }

        $this->maybe_ban_ip($reason);
    }

    private function is_immediate_exploit_probe($uri) {
        $path = (string) parse_url($uri, PHP_URL_PATH);
        $path = '/' . ltrim(rawurldecode($path), '/');
        $patterns = [
            '#/(?:\.env|env)(?:[./_-][^/]*)?$#i',
            '#/(?:credentials?|account|key|keyfile|service[-_]?account)(?:\.[a-z0-9_-]+)?\.json$#i',
            '#/firebase-adminsdk[^/]*\.json$#i',
            '#/(?:sftp|ftp|database|db|config)(?:\.[a-z0-9_-]+)?\.json$#i',
            '#/(?:php-cgi(?:\.exe)?|trace\.axd|pom\.properties)$#i',
            '#/(?:graphql|gql|_catalog|server-status|phpinfo)(?:/|$)#i',
            '#/(?:\.git|\.svn|\.hg)(?:/|$)#i',
            '#/(?:wp-config\.php|xmlrpc\.php|composer\.json)(?:$|/)#i',
            '#/(?:wso|shell|chosen|adminfuns|inputs|simple)\.php$#i',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $path)) return true;
        }
        return false;
    }

    private function probe_label($uri) {
        $path = (string) parse_url($uri, PHP_URL_PATH);
        $label = trim(basename($path));
        return $label !== '' ? sanitize_text_field($label) : 'high-confidence signature';
    }

    private function looks_like_exploit($uri) {
        $patterns = [
            'wp_filemanager','filemanager','shell','wso','chosen.php','adminfuns','inputs.php',
            'simple.php','class.php','config.php','wp-load.php','xmlrpc.php','.env','.git',
            'composer.json','vendor/','backup','database.php','phpinfo','eval-stdin','wp-config'
        ];
        foreach ($patterns as $p) {
            if (stripos($uri, $p) !== false) return true;
        }
        return false;
    }

    private function record_event($reason, $risk, $status_code) {
        global $wpdb;
        $wpdb->insert(self::table_name(self::TABLE_EVENTS), [
            'ip' => $this->get_ip(),
            'user_agent' => $this->user_agent(),
            'method' => $this->method(),
            'uri' => $this->request_uri(),
            'reason' => sanitize_key($reason),
            'risk' => (int) $risk,
            'status_code' => (int) $status_code,
            'created_at' => current_time('mysql'),
        ], ['%s','%s','%s','%s','%s','%d','%d','%s']);
    }

    private function maybe_ban_ip($latest_reason) {
        global $wpdb;
        $settings = $this->settings();
        $events = self::table_name(self::TABLE_EVENTS);
        $bans = self::table_name(self::TABLE_BANS);
        $ip = $this->get_ip();
        if ($this->is_trusted_request() || $this->is_cloudflare_ip($ip)) return;
        $window_minutes = max(1, (int) $settings['window_minutes']);
        $threshold = max(1, (int) $settings['threshold_404']);
        $ban_hours = max(1, (int) $settings['ban_hours']);
        $since = date('Y-m-d H:i:s', current_time('timestamp') - ($window_minutes * 60));

        if (!empty($settings['php_only_mode'])) {
            $count = (int) $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$events} WHERE ip = %s AND created_at >= %s AND reason IN ('php_404','exploit_scan','sensitive_file_probe')",
                $ip,
                $since
            ));
        } else {
            $count = (int) $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$events} WHERE ip = %s AND created_at >= %s",
                $ip,
                $since
            ));
        }

        if ($count < $threshold) return;

        $risk_sum = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COALESCE(SUM(risk),0) FROM {$events} WHERE ip = %s AND created_at >= %s",
            $ip,
            $since
        ));

        $until = date('Y-m-d H:i:s', current_time('timestamp') + ($ban_hours * HOUR_IN_SECONDS));
        $wpdb->replace(self::table_name(self::TABLE_BANS), [
            'ip' => $ip,
            'reason' => 'Auto-ban: ' . sanitize_text_field($latest_reason) . ' / ' . (int) $count . ' suspicious 404s',
            'risk' => $risk_sum,
            'banned_until' => $until,
            'created_at' => current_time('mysql'),
        ], ['%s','%s','%d','%s','%s']);
    }

    public function admin_menu() {
        add_menu_page('IAQ Security Patrol', 'IAQ Patrol', 'manage_options', self::MENU_SLUG, [$this, 'render_admin'], 'dashicons-shield-alt', 28);
    }

    public function handle_unban() {
        if (!current_user_can('manage_options')) wp_die('Unauthorized');
        check_admin_referer('iaq_security_unban');
        global $wpdb;
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if ($ip) $wpdb->delete(self::table_name(self::TABLE_BANS), ['ip' => $ip], ['%s']);
        wp_safe_redirect(admin_url('admin.php?page=' . self::MENU_SLUG . '&unbanned=1'));
        exit;
    }

    public function handle_clear_events() {
        if (!current_user_can('manage_options')) wp_die('Unauthorized');
        check_admin_referer('iaq_security_clear_events');
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE " . self::table_name(self::TABLE_EVENTS));
        wp_safe_redirect(admin_url('admin.php?page=' . self::MENU_SLUG . '&cleared=1'));
        exit;
    }

    public function render_admin() {
        if (!current_user_can('manage_options')) return;
        global $wpdb;
        self::create_tables();
        $events = self::table_name(self::TABLE_EVENTS);
        $bans = self::table_name(self::TABLE_BANS);
        $settings = $this->settings();

        $active_bans = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$bans} WHERE banned_until > %s ORDER BY banned_until DESC LIMIT 100",
            current_time('mysql')
        ));
        $recent_events = $wpdb->get_results("SELECT * FROM {$events} ORDER BY id DESC LIMIT 100");
        $top_ips = $wpdb->get_results("SELECT ip, COUNT(*) AS hits, SUM(risk) AS risk_total, MAX(created_at) AS last_seen FROM {$events} GROUP BY ip ORDER BY hits DESC LIMIT 20");

        echo '<div class="wrap"><h1>IAQ Security Patrol</h1>';
        if (isset($_GET['unbanned'])) echo '<div class="notice notice-success is-dismissible"><p>IP unbanned.</p></div>';
        if (isset($_GET['cleared'])) echo '<div class="notice notice-warning is-dismissible"><p>Event log cleared.</p></div>';

        echo '<p><strong>Rule:</strong> ' . esc_html($settings['threshold_404']) . ' suspicious 404s within ' . esc_html($settings['window_minutes']) . ' minutes → ' . esc_html($settings['ban_hours']) . ' hour ban.</p>';
        echo '<p><strong>Mode:</strong> ' . (!empty($settings['php_only_mode']) ? 'Only suspicious PHP / exploit / sensitive-file 404s trigger bans.' : 'All 404s count.') . '</p>';
        echo '<p><strong>Exploit ban:</strong> High-confidence credential, environment, debug, registry, repository and executable probes are banned immediately for ' . esc_html($settings['ban_hours']) . ' hours.</p>';
        echo '<p><strong>Behavior patrol:</strong> ' . esc_html($settings['burst_hits']) . ' pages/' . esc_html($settings['burst_seconds']) . ' sec, ' . esc_html($settings['sustained_hits']) . ' pages/' . esc_html($settings['sustained_minutes']) . ' min, or ' . esc_html($settings['direct_hits']) . ' distinct direct pages/' . esc_html($settings['direct_minutes']) . ' min → ' . esc_html($settings['ban_hours']) . ' hour ban. Three crawler identities from one IP are blocked as a layer probe.</p>';
        echo '<p><strong>Trusted networks:</strong> Cloudflare edge IPs are never banned. Google, Bing, Yandex and Apple crawlers require forward-confirmed reverse DNS; OpenAI and Perplexity crawlers require a match against their published IP feeds. User-Agent names alone do not grant an exemption.</p>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:16px 0;">';
        wp_nonce_field('iaq_security_clear_events');
        echo '<input type="hidden" name="action" value="iaq_security_clear_events"><button class="button" onclick="return confirm(\'Clear all patrol events?\')">Clear Event Log</button></form>';

        echo '<hr><h2>Active Bans</h2><table class="widefat striped"><thead><tr><th>IP</th><th>Reason</th><th>Risk</th><th>Until</th><th>Action</th></tr></thead><tbody>';
        if (empty($active_bans)) echo '<tr><td colspan="5">No active bans.</td></tr>';
        foreach ((array) $active_bans as $ban) {
            echo '<tr><td><code>' . esc_html($ban->ip) . '</code></td><td>' . esc_html($ban->reason) . '</td><td>' . esc_html($ban->risk) . '</td><td>' . esc_html($ban->banned_until) . '</td><td>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field('iaq_security_unban');
            echo '<input type="hidden" name="action" value="iaq_security_unban"><input type="hidden" name="ip" value="' . esc_attr($ban->ip) . '"><button class="button">Unban</button></form></td></tr>';
        }
        echo '</tbody></table>';

        echo '<hr><h2>Top Suspicious IPs</h2><table class="widefat striped"><thead><tr><th>IP</th><th>Hits</th><th>Risk</th><th>Last Seen</th></tr></thead><tbody>';
        if (empty($top_ips)) echo '<tr><td colspan="4">No events yet.</td></tr>';
        foreach ((array) $top_ips as $row) {
            echo '<tr><td><code>' . esc_html($row->ip) . '</code></td><td>' . esc_html($row->hits) . '</td><td>' . esc_html($row->risk_total) . '</td><td>' . esc_html($row->last_seen) . '</td></tr>';
        }
        echo '</tbody></table>';

        echo '<hr><h2>Recent Patrol Events</h2><table class="widefat striped"><thead><tr><th>Date</th><th>IP</th><th>Reason</th><th>Risk</th><th>URI</th><th>User Agent</th></tr></thead><tbody>';
        if (empty($recent_events)) echo '<tr><td colspan="6">No events yet.</td></tr>';
        foreach ((array) $recent_events as $event) {
            echo '<tr><td>' . esc_html($event->created_at) . '</td><td><code>' . esc_html($event->ip) . '</code></td><td>' . esc_html($event->reason) . '</td><td>' . esc_html($event->risk) . '</td><td><code>' . esc_html(wp_trim_words($event->uri, 12, '...')) . '</code></td><td><small>' . esc_html(wp_trim_words($event->user_agent, 12, '...')) . '</small></td></tr>';
        }
        echo '</tbody></table></div>';
    }
}

IAQ_Security_Patrol::instance();
