<?php

declare(strict_types=1);

use Fisharebest\Webtrees\Registry;
use Komputeryk\Webtrees\ProxyAuth\ProxyAuthModule;

require __DIR__ . '/vendor/autoload.php';

return Registry::container()->get(ProxyAuthModule::class);
