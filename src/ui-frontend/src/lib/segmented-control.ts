// Space UI registry gap: the `lib/segmented-control` module referenced by the
// vendored `tabs` primitive is not published as a standalone registry item
// (spaceui.one/r/primitives-segmented-control.json returns 404 as of
// 2026-10-07). This shim reproduces the three exports tabs.tsx consumes.
// Recorded in docs/product/UI_DECISIONS.md.

export type SegmentedControlSize = 'default' | 'sm' | 'lg'

export const segmentedControlItemLayoutClassName =
  'h-8 px-3 text-sm data-[orientation=vertical]:w-full data-[orientation=vertical]:justify-start'

export const segmentedControlItemSizeClassNames: Record<SegmentedControlSize, string> = {
  default: 'h-8 px-3 text-sm',
  sm: 'h-7 px-2 text-xs',
  lg: 'h-9 px-4 text-sm',
}
