<?php

declare(strict_types=1);

namespace Komputeryk\Webtrees\ProxyAuth;

use Exception;
use IPLib\Factory as IPFactory;
use Fisharebest\Webtrees\Auth;
use Fisharebest\Webtrees\Contracts\UserInterface;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Log;
use Fisharebest\Webtrees\Module\AbstractModule;
use Fisharebest\Webtrees\Module\ModuleCustomInterface;
use Fisharebest\Webtrees\Module\ModuleCustomTrait;
use Fisharebest\Webtrees\Services\UserService;
use Fisharebest\Webtrees\Session;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ProxyAuthModule extends AbstractModule implements ModuleCustomInterface, MiddlewareInterface
{
    use ModuleCustomTrait;

    public const MODULE_DIR = __DIR__ . '/../';

    private UserService $userService;

    public function __construct()
    {
        $this->userService = new UserService();
    }

    public function boot(): void
    {
    }

    public function title(): string
    {
        return I18N::translate('LBL_MODULE_NAME');
    }

    public function description(): string
    {
        return I18N::translate('LBL_MODULE_DESCRIPTION');
    }

    public function customModuleAuthorName(): string
    {
        return 'Eryk Andrzejewski';
    }

    public function customModuleVersion(): string
    {
        return file_get_contents(static::MODULE_DIR . 'VERSION');
    }

    public function customModuleLatestVersionUrl(): string
    {
        return 'https://github.com/qwercik/webtrees-proxy-auth/raw/master/VERSION';
    }

    public function customModuleSupportUrl(): string
    {
        return 'https://github.com/qwercik/webtrees-proxy-auth';
    }

    public function customTranslations(string $language): array
    {
        $file = $this->getLangFilePath($language);
        return file_exists($file)
            ? require $file
            : require $this->getLangFilePath('en');
    }

    private function getLangFilePath(string $language): string
    {
        return $this->resourcesFolder() . "lang/{$language}.php";
    }

    public function resourcesFolder(): string
    {
        return static::MODULE_DIR . 'resources/';
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);
        $this->authenticateByHeader($request);
        return $response;
    }

    private function authenticateByHeader(ServerRequestInterface $request): void
    {
        $username = $request->getHeaderLine('Remote-User');
        if (empty($username)) {
            return;
        }

        if (!$this->isTrustedProxy($request)) {
            return;
        }

        if (Auth::user()?->userName() === $username) {
            return;
        }

        $user = $this->userService->findByIdentifier($username);
        if ($user === null) {
            Log::addAuthenticationLog('Login failed (no such user/email): ' . $username);
            return;
        }

        if ($user->getPreference(UserInterface::PREF_IS_EMAIL_VERIFIED) !== '1') {
            Log::addAuthenticationLog('Login failed (not verified by user): ' . $username);
            throw new Exception(I18N::translate('This account has not been verified. Please check your email for a verification message.'));
        }

        if ($user->getPreference(UserInterface::PREF_IS_ACCOUNT_APPROVED) !== '1') {
            Log::addAuthenticationLog('Login failed (not approved by admin): ' . $username);
            throw new Exception(I18N::translate('This account has not been approved. Please wait for an administrator to approve it.'));
        }

        $realName = $user->realName();
        Auth::login($user);

        $ip = $request->getAttribute('client-ip');
        Log::addAuthenticationLog("Logged in by reverse proxy from ip {$ip} as user {$username}/{$realName}");
        $user->setPreference(UserInterface::PREF_TIMESTAMP_ACTIVE, (string)time());
        Session::put('language', $user->getPreference(UserInterface::PREF_LANGUAGE));
        Session::put('theme', $user->getPreference(UserInterface::PREF_THEME));
        I18N::init($user->getPreference(UserInterface::PREF_LANGUAGE));
    }

    private function isTrustedProxy(ServerRequestInterface $request): bool
    {
        $trustedProxies = $request->getAttribute('trust_proxies');
        if (empty($trustedProxies)) {
            return false;
        }

        $clientIp = IPFactory::parseAddressString($request->getAttribute('client-ip'));
        foreach (explode(',', $trustedProxies) as $range) {
            $range = IPFactory::parseRangeString(trim($range));
            if ($range?->contains($clientIp)) {
                return true;
            }
        }

        return false;
    }
}
