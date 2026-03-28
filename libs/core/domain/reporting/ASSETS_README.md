# 📸 Assets Management - Guía de Uso

Este directorio contiene el sistema de gestión de assets visuales para mcp-verify.

## 📁 Estructura

```
libs/core/domain/reporting/
├── assets.ts           # ← Módulo principal (EDITAR AQUÍ)
├── hero-image.ts       # ← Imagen JPEG legacy (reemplazar en v1.1)
└── ASSETS_README.md    # ← Este archivo
```

## 🎯 Cuándo Agregar Imágenes

### v1.0 (AHORA)
- ✅ **ASCII Art CLI** - Ya incluido, no requiere imágenes
- ⏳ **Iconos/Logo** - Opcional, puedes agregarlo cuando tengas diseños

### v1.1 (POST-LANZAMIENTO)
- 🎨 **Yogui SVG** - Estados de la mascota para reportes HTML
- 🖼️ **Hero Image optimizado** - Reemplazar JPEG por WebP <20KB

---

## 🔧 Cómo Agregar Imágenes

### 1️⃣ SVG (RECOMENDADO para iconos/logos)

**Paso 1:** Optimiza tu SVG
- Ve a: https://jakearchibald.github.io/svgomg/
- Sube tu SVG
- Copia el código optimizado

**Paso 2:** Agrega a `assets.ts`
```typescript
// En la sección ICONOS
export const ICONS = {
  shield: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>`,
  // ... otros iconos
};
```

**Ventajas:**
- ✅ Escalable sin pérdida de calidad
- ✅ Peso mínimo (<1KB por icono)
- ✅ Fácil de editar/modificar

---

### 2️⃣ WebP/PNG (Para fotos/ilustraciones)

**Paso 1:** Optimiza la imagen
- Usa: https://squoosh.app/
- Formato: WebP (mejor compresión)
- Calidad: 75-85%
- **Target: <20KB**

**Paso 2:** Convierte a Base64
- Ve a: https://www.base64-image.de/
- Sube tu imagen optimizada
- Copia el código Base64

**Paso 3:** Agrega a `assets.ts`
```typescript
// Para Yogui o Hero Image
export const YOGUI_STATES = {
  scanning: 'data:image/webp;base64,UklGRiQAAABXRUJQVlA4IBgAAAAwAQCdASoBAAEAAwA0JaQAA3AA/vuUAAA=',
  // ... otros estados
};
```

**Ventajas:**
- ✅ Mejor calidad/peso que JPEG
- ✅ Soporte transparencia
- ✅ Inline en HTML (reporte portable)

---

### 3️⃣ JPEG (ÚLTIMO RECURSO)

Solo si WebP no es opción (compatibilidad legacy).

**Proceso similar a WebP:**
1. Optimiza con https://tinyjpg.com/
2. Calidad: 70-80%
3. Convierte a Base64
4. Agrega a `assets.ts`

---

## 📏 Performance Budget

| Asset Type | Max Size | Status |
|------------|----------|--------|
| Iconos SVG | Sin límite | ✅ Escalables |
| Logo/Brand | <5KB | ⏳ Pendiente |
| Hero Image | <20KB | ❌ Actual: >100KB |
| Yogui States | <10KB cada uno | ⏳ v1.1 |
| **Total Inline** | **<50KB** | 🎯 Target |

---

## 🎨 Assets Necesarios

### Prioridad ALTA (v1.0)
```
[ ] Logo principal (SVG, 32x32px)
    └─ Para header de reportes HTML
```

### Prioridad MEDIA (v1.1)
```
[ ] Yogui - Estado "scanning" (SVG/WebP, 120x120px)
[ ] Yogui - Estado "shield" (SVG/WebP, 120x120px)
[ ] Yogui - Estado "celebrating" (SVG/WebP, 120x120px)
[ ] Yogui - Estado "thinking" (SVG/WebP, 120x120px)
[ ] Hero Image optimizado (WebP, <20KB)
```

### Prioridad BAJA (Opcional)
```
[ ] Iconos personalizados (SVG)
    ├─ shield (escudo de seguridad)
    ├─ check (validación OK)
    ├─ alert (advertencia)
    ├─ copy (copiar código)
    ├─ info (información)
    ├─ download (descargar reporte)
    └─ baseline (comparación)
```

---

## 🔄 Workflow de Actualización

1. **Obtienes tu imagen** (diseño/foto/ilustración)
2. **Optimiza** según tipo (SVG/WebP/JPEG)
3. **Valida peso** con `validateAssetSize()` en assets.ts
4. **Convierte a Base64** (si no es SVG)
5. **Edita `assets.ts`** y reemplaza el string vacío `''`
6. **Test** - Genera un reporte HTML y verifica que se vea bien
7. **Commit** con mensaje: `feat(assets): add [nombre] image`

---

## 🧪 Testing

Para probar que tus imágenes funcionan:

```bash
# Genera un reporte HTML de prueba
npm run test:reports

# Abre el reporte generado en:
# reports/[fecha]/report.html

# Verifica:
# ✅ Imagen se ve correctamente
# ✅ No rompe el layout
# ✅ Carga rápido (<2s)
```

---

## 🚨 Troubleshooting

### La imagen no se ve
- ✅ Verifica que el string Base64 esté completo
- ✅ Incluye el prefijo: `data:image/webp;base64,`
- ✅ No hay saltos de línea en el medio

### Imagen muy pesada
- ❌ Reduce calidad (70-80% es suficiente)
- ❌ Baja resolución (no necesitas 4K para iconos)
- ❌ Usa WebP en lugar de PNG/JPEG

### SVG no escala bien
- ✅ Asegúrate que tenga atributo `viewBox`
- ✅ Quita dimensiones fijas (width/height en px)
- ✅ Usa unidades relativas

---

## 📚 Recursos Útiles

- **Optimización SVG:** https://jakearchibald.github.io/svgomg/
- **Optimización WebP/PNG:** https://squoosh.app/
- **Conversión Base64:** https://www.base64-image.de/
- **Iconos gratis (SVG):** https://lucide.dev/
- **Ilustraciones:** https://undraw.co/

---

## 🤝 Contribución

Si agregas assets, documenta en el commit:
```
feat(assets): add Yogui scanning state (8.2KB WebP)

- Optimized with Squoosh (quality 80%)
- Base64 embedded for portable reports
- Performance budget: OK (8.2KB < 10KB)
```

---

**Última actualización:** 09/02/2026
**Versión:** 1.0
**Mantenedor:** @finkrodriguez
