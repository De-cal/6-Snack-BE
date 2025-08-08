import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

export const s3 = new S3Client({
  region: "ap-northeast-2",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

export const uploadImageToS3 = async (file: Express.Multer.File) => {
  const fileKey = `products/${Date.now()}_${file.originalname}`;
  const bucketName = process.env.AWS_BUCKET_NAME!;

  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: fileKey,
    Body: file.buffer,
    ContentType: file.mimetype,
  });

  await s3.send(command);

  return `https://${bucketName}.s3.amazonaws.com/${fileKey}`;
};

const getCloudFrontUrl = (s3Key: string)=>{
  const cloudFrontDomain = process.env.CLOUDFRONT_DOMAIN;
  if(!cloudFrontDomain) {
    throw new Error("CLOUDFRONT_DOMAIN is not set")
  }
  return `https://${cloudFrontDomain}/${s3Key}`;
}