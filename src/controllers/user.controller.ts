import { TGetUsersQueryDto, TUpdatePasswordDto, TUpdateRoleDto, TUserIdParamsDto } from "../dtos/user.dto";
import userService from "../services/user.service";
import { RequestHandler } from "express";

/**
 * @swagger
 * tags:
 *   - name: User
 *     description: 최고관리자 전용 엔드포인트
 *   - name: User
 *     description: 일반 사용자 관련 엔드포인트
 */

/**
 * @swagger
 * /super-admin/users/invite:
 *   post:
 *     summary: (최고관리자) 유저 초대 생성
 *     description: SUPER_ADMIN 이 같은 회사에 새로운 사용자를 초대합니다. 초대 이메일이 발송되고 해당 초대 링크로 회원가입을 완료합니다.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, name, role, companyId, invitedById]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               name:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [USER, ADMIN]
 *                 description: SUPER_ADMIN 는 초대를 통해 생성할 수 없음
 *               companyId:
 *                 type: string
 *               invitedById:
 *                 type: string
 *               expiresInDays:
 *                 type: number
 *                 default: 7
 *     responses:
 *       201:
 *         description: 초대 성공
 *       400:
 *         description: 잘못된 요청
 *       401:
 *         description: 인증 실패
 *       403:
 *         description: 권한 없음 (SUPER_ADMIN 필수)
 */

/**
 * @swagger
 * /users/{userId}:
 *   get:
 *     summary: 유저 정보 조회
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: 조회할 유저 ID
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 유저 정보 조회 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "일반 유저 정보 조회 완료"
 *                 user:
 *                   type: object
 *                   properties:
 *                     company:
 *                       type: object
 *                       properties:
 *                         name:
 *                           type: string
 *                     name:
 *                       type: string
 *                     email:
 *                       type: string
 *                     role:
 *                       type: string
 *       400:
 *         description: 자기 자신의 정보만 조회 가능
 *       401:
 *         description: 인증 실패
 */
// 유저 프로필 조회
const getUserInfo: RequestHandler<TUserIdParamsDto> = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    const currentUser = req.user!;

    const result = await userService.getUserInfo(userId, currentUser);
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
};

/**
 * @swagger
 * /super-admin/users/{userId}:
 *   delete:
 *     summary: (최고관리자) 유저 삭제
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: 삭제할 유저 ID
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 유저 삭제 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "사용자가 성공적으로 삭제되었습니다."
 *       400:
 *         description: 최고관리자는 자기 자신을 삭제할 수 없음
 *       401:
 *         description: 인증 실패
 *       403:
 *         description: 권한 없음 (SUPER_ADMIN만 가능)
 *       404:
 *         description: 유저가 존재하지 않음
 */
// 유저 탈퇴
const deleteUser: RequestHandler<TUserIdParamsDto> = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    const currentUser = req.user!;

    const result = await userService.deleteUser(userId, currentUser);
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
};

/**
 * @swagger
 * /super-admin/users/{userId}/role:
 *   patch:
 *     summary: (최고관리자) 유저 권한 수정
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: 권한을 수정할 유저 ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - role
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [ADMIN, USER]
 *                 description: 변경할 권한
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 권한 수정 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "사용자 권한이 성공적으로 변경되었습니다."
 *                 role:
 *                   type: string
 *                   enum: [ADMIN, USER]
 *       400:
 *         description: 잘못된 권한 값 또는 최고관리자는 자기 자신의 권한을 변경할 수 없음
 *       401:
 *         description: 인증 실패
 *       403:
 *         description: 권한 없음 (SUPER_ADMIN만 가능)
 *       404:
 *         description: 유저가 존재하지 않음
 */
// 유저 권한 변경
const updateRole: RequestHandler<TUserIdParamsDto, any, TUpdateRoleDto> = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    const { role }: TUpdateRoleDto = req.body;
    const currentUser = req.user!;

    const result = await userService.updateRole(userId, role, currentUser);
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
};

/**
 * @swagger
 * /users/{userId}/password:
 *   patch:
 *     summary: 유저 비밀번호 수정
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: 비밀번호를 수정할 유저 ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newPassword
 *               - newPasswordConfirm
 *             properties:
 *               newPassword:
 *                 type: string
 *                 description: 새로운 비밀번호
 *               newPasswordConfirm:
 *                 type: string
 *                 description: 새로운 비밀번호 확인
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 비밀번호 수정 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "비밀번호가 성공적으로 변경되었습니다."
 *       400:
 *         description: 자기 자신의 비밀번호만 변경 가능
 *       401:
 *         description: 인증 실패
 */
const updatePassword: RequestHandler<TUserIdParamsDto, any, TUpdatePasswordDto> = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    const passwordData: TUpdatePasswordDto = req.body;
    const currentUser = req.user!;

    const result = await userService.updatePassword(userId, passwordData, currentUser);
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
};

/**
 * @swagger
 * /super-admin/users:
 *   get:
 *     summary: (최고관리자) 회사 유저 목록 조회
 *     tags: [User]
 *     parameters:
 *       - in: query
 *         name: name
 *         schema:
 *           type: string
 *         description: 유저 이름으로 검색 (선택사항)
 *       - in: query
 *         name: cursor
 *         schema:
 *           type: string
 *         description: 페이지네이션 커서 (선택사항)
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 5
 *         description: 한 번에 가져올 개수 (선택사항)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 회사 유저 목록 조회 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "회사 유저 목록 조회 완료"
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       email:
 *                         type: string
 *                       name:
 *                         type: string
 *                       role:
 *                         type: string
 *                         enum: [ADMIN, USER]
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     hasNext:
 *                       type: boolean
 *                     hasPrev:
 *                       type: boolean
 *                     nextCursor:
 *                       type: string
 *                     prevCursor:
 *                       type: string
 *       401:
 *         description: 인증 실패
 *       403:
 *         description: 권한 없음 (SUPER_ADMIN만 가능)
 */
//  유저 조회
const getUsersByCompany: RequestHandler<{}, any, {}, TGetUsersQueryDto> = async (req, res, next) => {
  try {
    const currentUser = req.user!;
    const result = await userService.getUsersByCompany(currentUser, req.query);
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
};

// 내 정보 조회
const getMe: RequestHandler = async (req, res, next) => {
  try {
    if (!req.user) {
      throw new Error("사용자 정보를 찾을 수 없습니다. 다시 로그인해 주세요.");
    }
    const user = await userService.getMe(req.user.id);
    res.status(200).json({ user });
  } catch (error) {
    next(error);
  }
};
export default { deleteUser, updateRole, updatePassword, getUsersByCompany, getUserInfo, getMe };
