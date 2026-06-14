package com.example.myphishingapp;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

/**
 * CircularProgressView — custom arc gauge for phishing risk score (0–100).
 * Colour transitions: green (0–30) → orange (31–60) → red (61–100).
 */
public class CircularProgressView extends View {

    private Paint bgPaint, progressPaint, trackPaint;
    private RectF arcRect;
    private int progress = 0;            // 0–100
    private float strokeWidth;

    // Arc sweeps 270° starting from 135° (bottom-left to bottom-right)
    private static final float START_ANGLE = 135f;
    private static final float SWEEP_MAX   = 270f;

    public CircularProgressView(Context context) {
        super(context); init(context);
    }
    public CircularProgressView(Context context, AttributeSet attrs) {
        super(context, attrs); init(context);
    }
    public CircularProgressView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle); init(context);
    }

    private void init(Context ctx) {
        float density = ctx.getResources().getDisplayMetrics().density;
        strokeWidth   = 10f * density;

        // Background track
        trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        trackPaint.setStyle(Paint.Style.STROKE);
        trackPaint.setStrokeWidth(strokeWidth);
        trackPaint.setStrokeCap(Paint.Cap.ROUND);
        trackPaint.setColor(0xFF2A2A3A);

        // Progress arc
        progressPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        progressPaint.setStyle(Paint.Style.STROKE);
        progressPaint.setStrokeWidth(strokeWidth);
        progressPaint.setStrokeCap(Paint.Cap.ROUND);
        progressPaint.setColor(0xFF2ECC71);

        arcRect = new RectF();
    }

    /**
     * Set progress (0–100) and redraw with colour transition.
     */
    public void setProgress(int value) {
        this.progress = Math.max(0, Math.min(100, value));
        // Interpolate colour: green→orange→red
        if (progress <= 30) {
            progressPaint.setColor(0xFF2ECC71);  // green
        } else if (progress <= 60) {
            progressPaint.setColor(0xFFF39C12);  // orange
        } else {
            progressPaint.setColor(0xFFE8394A);  // red
        }
        invalidate();
    }

    public int getProgress() { return progress; }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float cx  = getWidth()  / 2f;
        float cy  = getHeight() / 2f;
        float rad = (Math.min(cx, cy)) - strokeWidth / 2f - 4f;

        arcRect.set(cx - rad, cy - rad, cx + rad, cy + rad);

        // Draw background track
        canvas.drawArc(arcRect, START_ANGLE, SWEEP_MAX, false, trackPaint);

        // Draw progress arc
        float sweep = SWEEP_MAX * (progress / 100f);
        if (sweep > 0) {
            canvas.drawArc(arcRect, START_ANGLE, sweep, false, progressPaint);
        }
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        // Square view
        int size = Math.min(
                resolveSize(200, widthSpec),
                resolveSize(200, heightSpec)
        );
        setMeasuredDimension(size, size);
    }
}