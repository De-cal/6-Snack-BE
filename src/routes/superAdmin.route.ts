import { Router } from "express";
import authenticateToken from "../middlewares/jwtAuth.middleware";
import authorizeRoles from "../middlewares/authorizeRoles.middleware";
import userController from "../controllers/user.controller";
import companyController from "../controllers/company.controller";

const superAdminRouter = Router();

// 회원 탈퇴
superAdminRouter.delete("/users/:userId", authenticateToken, authorizeRoles("SUPER_ADMIN"), userController.deleteUser);

// 회원 권한 수정
superAdminRouter.patch(
  "/users/:userId/role",
  authenticateToken,
  authorizeRoles("SUPER_ADMIN"),
  userController.updateRole,
);

// 회사명, 최고관리자 비밀번호 수정
superAdminRouter.patch(
  "/users/:userId/company",
  authenticateToken,
  authorizeRoles("SUPER_ADMIN"),
  companyController.updateCompanyInfo,
);

// 최고관리자의 회사 유저목록 조회
superAdminRouter.get("/users", authenticateToken, authorizeRoles("SUPER_ADMIN"), userController.getUsersByCompany);

export default superAdminRouter;
