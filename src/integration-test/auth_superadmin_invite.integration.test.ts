import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import app from '../app';

const prisma = new PrismaClient();

/**
 * 간단 통합 테스트: Auth & Invite 관련 핵심 성공 플로우만 검증
 * 순서 중요: SUPER_ADMIN 회원가입 -> 로그인 -> 초대 생성 -> 초대 회원가입 -> 토큰 리프레시 -> 로그아웃
 */
describe('Auth & Invite Integration (Simple Flow)', () => {
  let superAdminEmail = 'superadmin@example.com';
  let superAdminPassword = 'StrongP@ssw0rd!';
  let superAdminAccessCookie: string[] = [];
  let superAdminRefreshCookie: string[] = [];
  let superAdminUserId: string;
  let companyId: number;
  let superAdminInviteId: string;

  beforeAll(async () => {
    await prisma.$connect();
    // 의존성 있는 순서로 테이블 정리 (CASCADE)
    await prisma.$executeRaw`TRUNCATE TABLE "Payment" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Receipt" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Order" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "CartItem" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Favorite" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Product" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Category" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "MonthlyBudget" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Invite" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "User" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "Company" CASCADE`;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  test('POST /auth/signup SUPER_ADMIN 회원가입 성공', async () => {
    const res = await request(app)
      .post('/auth/signup')
      .send({
        email: superAdminEmail,
        name: '최고관리자',
        password: superAdminPassword,
        confirmPassword: superAdminPassword,
        companyName: '테스트회사',
        bizNumber: '999-99-99999'
      })
      .expect(201);

    expect(res.body).toHaveProperty('user');
    expect(res.body.user.role).toBe('SUPER_ADMIN');
    expect(res.body).toHaveProperty('company');
    companyId = res.body.company.id;
  });

  test('POST /auth/login SUPER_ADMIN 로그인 성공 (쿠키 수신)', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ email: superAdminEmail, password: superAdminPassword })
      .expect(200);

    expect(res.body).toHaveProperty('user');
    superAdminUserId = res.body.user.id;
    const setCookieRaw = res.headers['set-cookie'];
    const setCookie = Array.isArray(setCookieRaw) ? setCookieRaw : (setCookieRaw ? [setCookieRaw] : []);
    expect(setCookie.length).toBeGreaterThan(0);
    superAdminAccessCookie = setCookie.filter((c: string) => c.startsWith('accessToken='));
    superAdminRefreshCookie = setCookie.filter((c: string) => c.startsWith('refreshToken='));
    expect(superAdminAccessCookie.length).toBe(1);
    expect(superAdminRefreshCookie.length).toBe(1);
  });

  test('POST /super-admin/users/invite 최고관리자 유저 초대 성공', async () => {
    const res = await request(app)
      .post('/super-admin/users/invite')
      .set('Cookie', [...superAdminAccessCookie, ...superAdminRefreshCookie])
      .send({
        email: 'superadmin.invited@example.com',
        name: '초대된관리자',
        role: 'ADMIN',
        companyId: companyId,
        invitedById: superAdminUserId,
        expiresInDays: 3
      })
      .expect(201);
    expect(res.body).toHaveProperty('inviteId');
    expect(res.body).toHaveProperty('inviteLink');
    superAdminInviteId = res.body.inviteId;
  });

  test('POST /auth/signup/:inviteId 초대 링크 회원가입 성공', async () => {
    const res = await request(app)
      .post(`/auth/signup/${superAdminInviteId}`)
      .send({ password: 'UserP@ssw0rd!', confirmPassword: 'UserP@ssw0rd!' })
      .expect(201);

    expect(res.body).toHaveProperty('user');
    expect(res.body.user.email).toBe('superadmin.invited@example.com');
  });

  test('POST /auth/refresh-token 토큰 갱신 성공', async () => {
    const res = await request(app)
      .post('/auth/refresh-token')
      .set('Cookie', [...superAdminAccessCookie, ...superAdminRefreshCookie])
      .expect(200);

    expect(res.body).toHaveProperty('message');
    const setCookieRaw = res.headers['set-cookie'];
    const setCookie = Array.isArray(setCookieRaw) ? setCookieRaw : (setCookieRaw ? [setCookieRaw] : []);
    const newAccess = setCookie.filter((c: string) => c.startsWith('accessToken='));
    const newRefresh = setCookie.filter((c: string) => c.startsWith('refreshToken='));
    expect(newAccess.length).toBe(1);
    expect(newRefresh.length).toBe(1);
    superAdminAccessCookie = newAccess;
    superAdminRefreshCookie = newRefresh;
  });

  test('POST /auth/logout 로그아웃 성공 (쿠키 제거)', async () => {
    const res = await request(app)
      .post('/auth/logout')
      .set('Cookie', [...superAdminAccessCookie, ...superAdminRefreshCookie])
      .expect(200);

    expect(res.body).toHaveProperty('message');
  });
});
