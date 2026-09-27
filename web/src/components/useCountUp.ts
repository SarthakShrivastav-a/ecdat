import { useEffect, useRef, useState } from 'react'

const reduced = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

/**
 * Roll a number to its new value so a recompute reads as movement rather than a repaint.
 * Skips straight to the target on first paint, for large jumps, and when the user asked for
 * reduced motion - the animation is here to show *change*, not to make people wait.
 */
export function useCountUp(target: number, ms = 420): number {
  const [n, setN] = useState(target)
  const from = useRef(target)
  const raf = useRef(0)

  useEffect(() => {
    const start = from.current
    if (start === target || reduced()) {
      from.current = target
      setN(target)
      return
    }
    const t0 = performance.now()
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms)
      const eased = 1 - Math.pow(1 - p, 3)
      setN(Math.round(start + (target - start) * eased))
      if (p < 1) raf.current = requestAnimationFrame(tick)
      else from.current = target
    }
    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [target, ms])

  return n
}
