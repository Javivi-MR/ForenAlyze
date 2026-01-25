from flask import render_template, redirect, url_for, request, flash
from flask_login import login_required, logout_user, current_user
from . import app
from .extensions import db
from .models import User
from app.analysis.pipeline import analyze_file
from app.models import File, AnalysisResult, Alert

@app.route('/edit_user', methods=['GET', 'POST'])
@login_required
def edit_user():
    if request.method == 'POST':
        username = request.form.get('username')
        image_url = request.form.get('image_url')
        if username:
            current_user.username = username
        if image_url:
            current_user.image_url = image_url
        db.session.commit()
        flash('User updated', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_user.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file_path = saved_file_path
    file_record = File(
        filename=filename,
        user_id=current_user.id,
    )
    db.session.add(file_record)
    db.session.commit()

    analysis = analyze_file(file_path)
    analysis_record = AnalysisResult(
        file_id=file_record.id,
        user_id=current_user.id,
        yara_result=str(analysis['yara']),
        clamav_result=str(analysis['clamav']),
        virustotal_result=str(analysis['virustotal']),
        severity='info',  # calcular según resultado
        summary='Resumen del análisis'
    )
    db.session.add(analysis_record)
    db.session.commit()

    return redirect(url_for('dashboard'))