import { TUpdateCompanyInfoDto, TUpdateCompanyInfoResponseDto } from "../dtos/company.dto";
import companyRepository from "../repositories/company.repository";
import { BadRequestError } from "../types/error";
import { TCurrentUser } from "../types/user.types";
import userService from "./user.service";

const updateCompanyInfo = async (
  userId: string,
  updateData: TUpdateCompanyInfoDto,
  currentUser: TCurrentUser,
  companyId: number,
): Promise<TUpdateCompanyInfoResponseDto> => {
  // updateData를 봐서 updateData.companyName 있으면 회사명 변경 실행
  const newCompanyName = updateData.companyName;
  let newPasswordData = updateData.passwordData;
  let updatedCompany = null;

  // 새로운 회사이름 혹은 비밀번호 둘중하나는 있어야 변경 가능
  if (!newCompanyName && !newPasswordData) {
    throw new BadRequestError("최소 하나의 필드는 변경되어야 합니다.");
  }

  // 새로운 회사이름 적용
  if (newCompanyName) {
    updatedCompany = await companyRepository.updateCompanyName(companyId, newCompanyName);
  }

  // 새로운 비밀번호 적용
  if (newPasswordData) {
    await userService.updatePassword(
      userId,
      {
        newPassword: newPasswordData.newPassword,
        newPasswordConfirm: newPasswordData.newPasswordConfirm,
      },
      currentUser,
    );
  }

  // 응답 데이터 구성
  const company = updatedCompany || (await companyRepository.findCompanyById(companyId));

  if (!company) {
    throw new BadRequestError("회사 정보가 존재하지 않습니다.");
  }

  return {
    message: "회사 정보가 업데이트 되었습니다",
    company: {
      id: company.id,
      name: company.name,
    },
  };
};

export default { updateCompanyInfo };
