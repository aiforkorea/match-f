# apps/admin/views.py
import datetime
from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func, or_
# --- WTForms Imports ---
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

from apps.admin.forms import CreateUserForm, EditUserForm

from . import admin
from apps.dbmodels import Log, User, UserType
from apps.decorators import admin_required
from apps.extensions import db
from werkzeug.security import generate_password_hash # 비밀번호 해싱을 위해 사용
def log_action(title, summary, target_user_id=None, status_code=200):
    """관리자 행동을 로그로 기록하는 헬퍼 함수"""
    try:
        new_log = Log(
            user_id=current_user.id,
            target_user_id=target_user_id,
            endpoint=request.path,
            log_title=title,
            log_summary=summary,
            remote_addr=request.remote_addr,
            response_status_code=status_code,
        )
        db.session.add(new_log)
    except Exception as e:
        # 로깅 실패가 주 작업에 영향을 주지 않도록 처리
        print(f"로깅 실패: {e}")
@admin.route('/dashboard')
@admin_required
def dashboard():
    total_users = User.query.count()
    total_services = 3  # AIService.query.count()
    pending_subscriptions = 4 # Subscription.query.filter_by(status='pending').count()
    
    # 최근 7일간 서비스 사용량 (로그인 제외)
    #seven_days_ago = datetime.now() - datetime.timedelta(days=7)
    recent_service_usage = 0

    #recent_service_usage = db.session.query(func.sum(UsageLog.usage_count))\
    #                            .filter(UsageLog.timestamp >= seven_days_ago)\
    #                            .filter(UsageLog.usage_type.notin_([UsageLog.UsageType.LOGIN]))\
    #                            .scalar() or 0

    return render_template('admin/dashboard.html',
                           title='관리자 대시보드',
                           total_users=total_users,
                           total_services=total_services,
                           pending_subscriptions=pending_subscriptions,
                           recent_service_usage=recent_service_usage)
@admin.route('/users', methods=['GET'])
@admin_required
def users():
    PER_PAGE = 10
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '', type=str)
    # logging
    current_app.logger.debug("search_query: %s", search_query)
    # --- New search parameters ---
    user_type_query = request.args.get('user_type', '', type=str) # 'admin', 'expert', or 'user'
    is_active_query = request.args.get('is_active', '', type=str) # 'true', 'false', or ''
    created_at_query = request.args.get('created_at', '', type=str) # YYYY-MM-DD format
    # ---------------------------
    users_query = User.query
    # logging
    current_app.logger.debug("users_query: %s", users_query)

    # 검색 기능 (사용자 이름 또는 이메일)
    if search_query:
        users_query = users_query.filter(
            or_(
                User.username.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%')
            )
        )
    # 사용자 타입(관리자, 전문가, 사용자) 여부 필터링
#    if user_type_query :
#        if user_type_query == 'admin': 
#            users_query = users_query.filter(User.user_type == UserType.ADMIN)
#        elif user_type_query == 'expert':
#            users_query = users_query.filter(User.user_type == UserType.EXPERT)
#        elif user_type_query == 'user':
#            users_query = users_query.filter(User.user_type == UserType.USER)
# 동일 코드
    if user_type_query and user_type_query in [e.value for e in UserType]:
        users_query = users_query.filter(User.user_type == UserType(user_type_query))

    # 활성 상태 필터링
#    if is_active_query:
#        if is_active_query == 'true':
#            users_query = users_query.filter(User.is_active == True)
#        elif is_active_query == 'false':
#            users_query = users_query.filter(User.is_active == False)
# 동일 코드
    if is_active_query:
        is_active_bool = is_active_query.lower()=='true'
        users_query = users_query.filter(User.is_active == is_active_bool)
    # 가입일 필터링
    if created_at_query:
        try:
            # Parse the date string. We want to filter for users created ON that specific date.
            # So, from the start of that day up to the end of that day.
            search_date = datetime.datetime.strptime(created_at_query, '%Y-%m-%d').date()
            start_of_day = datetime.datetime.combine(search_date, datetime.time.min)
            end_of_day = datetime.datetime.combine(search_date, datetime.time.max)
            users_query = users_query.filter(User.created_at >= start_of_day, User.created_at <= end_of_day)
            #users_query = users_query.filter(User.created_at.between(start_of_day, end_of_day))
        except ValueError:
            flash('유효하지 않은 가입일 형식입니다. YYYY-MM-DD 형식으로 입력해주세요.', 'warning')
            created_at_query = ""
    # 페이지네이션 적용
    users_pagination = users_query.order_by(User.created_at.desc()).paginate(page=page, per_page=PER_PAGE, error_out=False)
    users = users_pagination.items
    # request.args에서 'page'만 뺀 딕셔너리 준비해서 템플릿에 넘긴다
    filtered_args = request.args.to_dict(flat=True)
    filtered_args.pop('page', None)
    return render_template(
        'admin/users.html',
        title='사용자 관리',
        users=users_pagination.items,
        pagination=users_pagination,
        search_query=search_query,
        user_type_query=user_type_query,
        is_active_query=is_active_query,
        created_at_query=created_at_query,
        UserType=UserType,           # 템플릿에서 Enum을 사용하기 위해 전달
        filtered_args=filtered_args, # <-- 추가
    )
@admin.route('/users/<int:user_id>/toggle_active', methods=['POST'])
@admin_required
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('자신의 계정 상태는 변경할 수 없습니다.', 'warning')
        return redirect(url_for('admin.users'))
    try:
        user.is_active = not user.is_active
        action = "활성" if user.is_active else "비활성"
        summary = f"'{user.username}'(ID:{user.id}) 계정을 {action} 상태로 변경."
        log_action(title="계정 상태 변경", summary=summary, target_user_id=user.id)
        db.session.commit()
        flash(f'{user.username} 계정 상태가 {action}으로 변경되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'계정 상태 변경 중 오류 발생: {e}', 'danger')
    return redirect(url_for('admin.users', **request.args)) # 기존 검색/필터 조건(request.args) 유지
@admin.route('/user_type_change/<int:user_id>', methods=['POST'])
@admin_required
def user_type_change(user_id):
    user = User.query.get_or_404(user_id)  # 1. 레코드 조회 
    print(f"user: {user}")   # log 사용
    if user.id == current_user.id:
        flash('자신의 관리자 권한은 변경할 수 없습니다.', 'warning')
        return redirect(url_for('admin.users'))
    new_user_type_str = request.form.get('user_type')
    if new_user_type_str in [e.value for e in UserType]:
        try:
            original_type = user.user_type.value
            user.user_type = UserType(new_user_type_str)
            summary = f"'{user.username}'(ID:{user.id}) 역할을 '{original_type}'에서 '{new_user_type_str}'(으)로 변경."
            log_action(title="사용자 역할 변경", summary=summary, target_user_id=user.id)
            db.session.commit()
            flash(f'사용자 역할 변경이 성공적으로 처리되었습니다.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'처리 중 오류가 발생했습니다: {e}', 'danger')
    else:
        flash('유효하지 않은 사용자 역할입니다.', 'danger')
    return redirect(url_for('admin.users', **request.args))
@admin.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(original_user=user)
    if form.validate_on_submit():
        try:
            original_username = user.username
            original_email = user.email
            user.username = form.username.data
            user.email = form.email.data
            summary = f"'{original_username}'(ID:{user.id}) 정보 변경. "
            if original_username != user.username:
                summary += f"이름: '{original_username}'->'{user.username}'. "
            if original_email != user.email:
                summary += f"이메일: '{original_email}'->'{user.email}'."
            log_action(title="사용자 정보 수정", summary=summary, target_user_id=user.id)
            db.session.commit()
            flash(f'{user.username}님의 정보가 성공적으로 수정되었습니다.', 'success')
            return redirect(url_for('admin.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'사용자 정보 수정 중 오류가 발생했습니다: {e}', 'danger')
    # GET 요청 시, 폼에 현재 사용자 정보를 채워서 전달
    form.username.data = user.username
    form.email.data = user.email
    return render_template('admin/edit_user.html', title=f'{user.username} 수정', form=form, user=user)
@admin.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('자신의 계정은 삭제할 수 없습니다.', 'warning')
        return redirect(url_for('admin.users'))

    try:
        username = user.username
        email = user.email
        # 사용자를 삭제하기 전에 로그를 먼저 기록합니다.
        summary = f"사용자 '{username}'(ID:{user_id}, Email:{email}) 계정 삭제."
        log_action(title="사용자 삭제", summary=summary, target_user_id=user_id)
        
        db.session.delete(user)
        db.session.commit()
        flash(f'{username} 계정이 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'사용자 삭제 중 오류가 발생했습니다: {e}', 'danger')

    return redirect(url_for('admin.users', **request.args))
@admin.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        print("create starts")
        try:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data,
                user_type=UserType(form.user_type.data),
                is_active=form.is_active.data
            )
            db.session.add(new_user)
            db.session.flush()
            summary = f"신규 사용자 '{new_user.username}'(ID:{new_user.id}, 역할:{new_user.user_type.value}) 생성."
            log_action(title="사용자 생성", summary=summary, target_user_id=new_user.id)
            db.session.commit()
            flash(f'{new_user.username} 사용자가 성공적으로 생성되었습니다.', 'success')
            return redirect(url_for('admin.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'사용자 생성 중 오류가 발생했습니다: {e}', 'danger')
    return render_template('admin/create_user.html', title='사용자 생성', form=form)