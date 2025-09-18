import { RequestHandler } from "express";
import favoriteService from "../services/favorite.service";
import { AuthenticationError } from "../types/error";
import { parseNumberOrThrow } from "../utils/parseNumberOrThrow";
import { TFavoriteParamsDto, TGetFavoritesQueryDto } from "../dtos/favorite.dto";

/**
 * @swagger
 * tags:
 *   - name: Favorite
 *     description: 찜 API
 */

/**
 * @swagger
 * /favorites:
 *   get:
 *     tags:
 *       - Favorite
 *     summary: 찜 목록 조회
 *     description: 로그인한 사용자의 찜한 상품 목록을 페이지네이션 방식으로 조회합니다.
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: query
 *         name: cursor
 *         schema:
 *           type: integer
 *         description: 다음 페이지를 위한 커서 (이전 응답의 마지막 찜 ID)
 *         example: 9
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 6
 *         description: 한 페이지당 항목 수
 *         example: 6
 *     responses:
 *       200:
 *         description: 찜 목록 조회 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 favorites:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       product:
 *                         type: object
 *                         properties:
 *                           id:
 *                             type: integer
 *                             example: 3
 *                           categoryId:
 *                             type: integer
 *                             example: 2
 *                           creatorId:
 *                             type: string
 *                             example: "user-2"
 *                           name:
 *                             type: string
 *                             example: "농심 새우깡"
 *                           price:
 *                             type: integer
 *                             example: 800
 *                           imageUrl:
 *                             type: string
 *                             format: uri
 *                             example: "https://d2fz535o8edlz5.cloudfront.net/products/nongshim-saewookang.png"
 *                           linkUrl:
 *                             type: string
 *                             format: uri
 *                             example: "https://example.com/nongshim-saewookang"
 *                           cumulativeSales:
 *                             type: integer
 *                             example: 200
 *                           createdAt:
 *                             type: string
 *                             format: date-time
 *                             example: "2025-01-03T00:00:00.000Z"
 *                           updatedAt:
 *                             type: string
 *                             format: date-time
 *                             example: "2025-01-03T00:00:00.000Z"
 *                           deletedAt:
 *                             type: string
 *                             format: date-time
 *                             nullable: true
 *                             example: null
 *                           category:
 *                             type: object
 *                             properties:
 *                               id:
 *                                 type: integer
 *                                 example: 2
 *                               name:
 *                                 type: string
 *                                 example: "과자"
 *                               parentId:
 *                                 type: integer
 *                                 example: 1
 *                           creator:
 *                             type: object
 *                             properties:
 *                               id:
 *                                 type: string
 *                                 example: "user-2"
 *                               email:
 *                                 type: string
 *                                 format: email
 *                                 example: "admin@codeit.com"
 *                               name:
 *                                 type: string
 *                                 example: "관리자"
 *                               role:
 *                                 type: string
 *                                 enum: [USER, ADMIN, SUPER_ADMIN]
 *                                 example: "ADMIN"
 *                 meta:
 *                   type: object
 *                   properties:
 *                     totalCount:
 *                       type: integer
 *                       example: 3
 *                     itemsPerPage:
 *                       type: integer
 *                       example: 6
 *                     totalPages:
 *                       type: integer
 *                       example: 1
 *                     nextCursor:
 *                       type: integer
 *                       nullable: true
 *                       example: 7
 *       401:
 *         description: 인증되지 않은 사용자
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 인증 토큰이 제공되지 않았습니다.
 *       500:
 *         description: 서버 오류
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 알 수 없는 서버 오류가 발생했습니다.
 */

const getFavorites: RequestHandler<{}, {}, {}, TGetFavoritesQueryDto> = async (req, res, next) => {
  const user = req.user;
  const cursor = req.query.cursor ? Number(req.query.cursor) : undefined;
  const limit = parseNumberOrThrow(req.query.limit ?? "6", "limit");

  if (!user) throw new AuthenticationError("유저 정보가 존재하지 않습니다.");

  const favorites = await favoriteService.getFavorites(user.id, { cursor, limit });

  res.status(200).json(favorites);
};

/**
 * @swagger
 * /favorites/{productId}:
 *   post:
 *     tags:
 *       - Favorite
 *     summary: 찜하기
 *     description: 로그인한 사용자가 특정 상품을 찜합니다. 이미 찜한 상품인 경우 오류가 발생합니다.
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: productId
 *         required: true
 *         schema:
 *           type: integer
 *         description: 찜할 상품의 ID
 *         example: 1
 *     responses:
 *       200:
 *         description: 찜하기 성공
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   example: 9
 *                 userId:
 *                   type: string
 *                   example: "user-1"
 *                 productId:
 *                   type: integer
 *                   example: 7
 *                 createdAt:
 *                   type: string
 *                   format: date-time
 *                   example: "2025-08-11T16:06:06.441Z"
 *       400:
 *         description: 이미 찜한 상품인 경우
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 이미 찜한 상품입니다.
 *       401:
 *         description: 인증되지 않은 사용자
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 인증 토큰이 제공되지 않았습니다.
 *       500:
 *         description: 서버 오류
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 알 수 없는 서버 오류가 발생했습니다.
 */

const createFavorite: RequestHandler<TFavoriteParamsDto> = async (req, res, next) => {
  const user = req.user;
  const productId = parseNumberOrThrow(req.params.productId, "productId");

  if (!user) throw new AuthenticationError("유저 정보가 존재하지 않습니다.");

  const favorite = await favoriteService.createFavorite(user.id, productId);

  res.status(200).json(favorite);
};

/**
 * @swagger
 * /favorites/{productId}:
 *   delete:
 *     tags:
 *       - Favorite
 *     summary: 찜 해제
 *     description: 로그인한 사용자가 특정 상품에 대해 찜을 해제합니다.
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: productId
 *         required: true
 *         schema:
 *           type: integer
 *         description: 찜을 해제할 상품의 ID
 *         example: 1
 *     responses:
 *       204:
 *         description: 찜 해제 성공 (본문 없음)
 *       400:
 *         description: 이미 찜 해제된 상품일 경우
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 이미 찜 해제한 상품입니다.
 *       401:
 *         description: 인증되지 않은 사용자
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 인증 토큰이 제공되지 않았습니다.
 *       500:
 *         description: 서버 오류
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: 알 수 없는 서버 오류가 발생했습니다.
 */

const deleteFavorite: RequestHandler<TFavoriteParamsDto> = async (req, res, next) => {
  const user = req.user;

  if (!user) throw new AuthenticationError("유저 정보가 존재하지 않습니다.");

  const productId = parseNumberOrThrow(req.params.productId, "productId");

  await favoriteService.deleteFavorite(user.id, productId);

  res.status(204).send();
};

export default {
  getFavorites,
  createFavorite,
  deleteFavorite,
};
