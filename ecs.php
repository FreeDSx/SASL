<?php

declare(strict_types=1);

use PhpCsFixer\Fixer\ArrayNotation\ArraySyntaxFixer;
use PhpCsFixer\Fixer\Import\NoUnusedImportsFixer;
use PhpCsFixer\Fixer\PhpTag\BlankLineAfterOpeningTagFixer;
use Symplify\CodingStandard\Fixer\Strict\BlankLineAfterStrictTypesFixer;
use Symplify\EasyCodingStandard\Config\ECSConfig;

return ECSConfig::configure()
    ->withPaths([
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->withPreparedSets(psr12: true)
    ->withConfiguredRule(
        ArraySyntaxFixer::class,
        ['syntax' => 'short'],
    )
    ->withRules([
        BlankLineAfterStrictTypesFixer::class,
        BlankLineAfterOpeningTagFixer::class,
        NoUnusedImportsFixer::class,
    ]);
