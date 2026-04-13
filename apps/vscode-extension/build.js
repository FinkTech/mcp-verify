/**
 * build.js — mcp-verify VS Code Extension
 *
 * Empaqueta la extensión en un único dist/extension.js sin depender de
 * esbuild-plugin-tsconfig-paths ni ningún plugin externo.
 * Resuelve las rutas del monorepo (@mcp-verify/*) con un plugin propio.
 */

const { build } = require('esbuild');
const path = require('path');
const fs = require('fs');

// Raíz del monorepo (dos niveles arriba de apps/vscode-extension/)
const MONOREPO_ROOT = path.resolve(__dirname, '..', '..');

/**
 * Mapeo explícito de paquetes internos del monorepo a su entry point real.
 * Si un paquete tiene tsconfig/paths distinto, ajustá la clave aquí.
 *
 * Convención: libs/<nombre>/src/index.ts
 * Si el entry point de algún paquete es distinto (ej. sin /src/), ajustarlo acá.
 */
const MONOREPO_PACKAGES = {
  '@mcp-verify/core':      path.join(MONOREPO_ROOT, 'libs', 'core',      'src', 'index.ts'),
  '@mcp-verify/shared':    path.join(MONOREPO_ROOT, 'libs', 'shared',    'src', 'index.ts'),
  '@mcp-verify/transport': path.join(MONOREPO_ROOT, 'libs', 'transport', 'src', 'index.ts'),
  '@mcp-verify/protocol':  path.join(MONOREPO_ROOT, 'libs', 'protocol',  'src', 'index.ts'),
  '@mcp-verify/fuzzer':    path.join(MONOREPO_ROOT, 'libs', 'fuzzer',    'src', 'index.ts'),
};

/**
 * Fallback: si libs/<nombre>/src/index.ts no existe, intenta libs/<nombre>/index.ts
 * Esto evita fallos silenciosos por convención de carpeta distinta.
 */
function resolvePackagePath(pkg, primary) {
  if (fs.existsSync(primary)) return primary;

  const fallbacks = [
    primary.replace(/[\\/]src[\\/]index\.ts$/, '/index.ts'),
    primary.replace(/[\\/]src[\\/]index\.ts$/, '/src/index.js'),
    primary.replace(/[\\/]src[\\/]index\.ts$/, '/dist/index.js'),
  ];

  for (const fb of fallbacks) {
    if (fs.existsSync(fb)) {
      console.warn(`[resolve-monorepo] ${pkg}: usando fallback → ${fb}`);
      return fb;
    }
  }

  throw new Error(
    `[resolve-monorepo] No se encontró entry point para "${pkg}".\n` +
    `  Ruta principal intentada: ${primary}\n` +
    `  Revisá MONOREPO_PACKAGES en build.js.`
  );
}

/**
 * Plugin esbuild: intercepta imports de @mcp-verify/* y los redirige
 * al archivo TypeScript real dentro del monorepo.
 * No depende de ningún paquete externo.
 */
const resolveMonorepoPlugin = {
  name: 'resolve-monorepo',
  setup(build) {
    // Captura exacto: '@mcp-verify/core' y también '@mcp-verify/core/algo'
    build.onResolve({ filter: /^@mcp-verify\// }, (args) => {
      // Buscar la entrada más larga que coincida como prefijo
      const exactMatch = MONOREPO_PACKAGES[args.path];
      if (exactMatch) {
        return { path: resolvePackagePath(args.path, exactMatch) };
      }

      // Subpaths: '@mcp-verify/core/utils/foo' → libs/core/src/utils/foo.ts
      for (const [pkg, entry] of Object.entries(MONOREPO_PACKAGES)) {
        if (args.path.startsWith(pkg + '/')) {
          const subPath = args.path.slice(pkg.length + 1); // 'utils/foo'
          const dir = path.dirname(resolvePackagePath(pkg, entry));
          const candidates = [
            path.join(dir, subPath + '.ts'),
            path.join(dir, subPath + '.js'),
            path.join(dir, subPath, 'index.ts'),
          ];
          for (const c of candidates) {
            if (fs.existsSync(c)) return { path: c };
          }
          throw new Error(
            `[resolve-monorepo] Subpath no encontrado: "${args.path}"\n` +
            `  Candidatos probados:\n${candidates.map(c => '    ' + c).join('\n')}`
          );
        }
      }

      // No es un paquete local conocido, dejar que esbuild lo resuelva normal
      return undefined;
    });
  },
};

// ─── Configuración principal ────────────────────────────────────────────────

const isProduction = process.env.NODE_ENV === 'production';

build({
  entryPoints: ['src/extension.ts'],
  bundle: true,
  platform: 'node',
  target: 'node18',

  // vscode SIEMPRE debe ser externo: lo provee el host en runtime
  external: ['vscode'],

  outfile: 'dist/extension.js',

  minify: isProduction,
  sourcemap: true,         // siempre útil, .vscodeignore excluye el .map en prod

  // El loader ts está incluido en esbuild sin plugins adicionales
  loader: { '.ts': 'ts' },

  // Resuelve los paquetes del monorepo
  plugins: [resolveMonorepoPlugin],

  // Evita que esbuild reescriba require() de módulos nativos de Node
  // (no necesario para VS Code, pero útil si se agregan deps nativas)
  define: {
    'process.env.NODE_ENV': JSON.stringify(isProduction ? 'production' : 'development'),
  },

  logLevel: 'info',   // Muestra exactamente qué archivos incluye en el bundle
}).then(() => {
  // Verificación explícita: el archivo de salida debe existir y tener contenido
  const outfile = path.join(__dirname, 'dist', 'extension.js');
  const stat = fs.statSync(outfile);
  if (stat.size < 100) {
    throw new Error(`dist/extension.js se generó pero parece vacío (${stat.size} bytes). Revisá los logs arriba.`);
  }
  console.log(`\n✓ Build exitoso → dist/extension.js (${(stat.size / 1024).toFixed(1)} KB)`);
}).catch((err) => {
  console.error('\n✗ Build falló:', err.message || err);
  process.exit(1);
});
