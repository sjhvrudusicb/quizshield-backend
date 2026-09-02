import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import dotenv from "dotenv";

dotenv.config();

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});

const prisma = new PrismaClient({ adapter });

const users = [
  { username: "ali", pin: "1234" },
  { username: "aimal-khan", pin: "03160" },
  { username: "qasim", pin: "56134" },
  { username: "mahad", pin: "78542" },
  { username: "muhammad-fahad", pin: "46973" },
  { username: "awais", pin: "74381" },
];

async function main() {
  // Clear existing data
  await prisma.answer.deleteMany();
  await prisma.attempt.deleteMany();
  await prisma.question.deleteMany();
  await prisma.quiz.deleteMany();
  await prisma.user.deleteMany();

  // Create users
  for (const user of users) {
    await prisma.user.create({ data: user });
  }
  console.log(`Created ${users.length} users`);

  // Create Math Quiz with 10 MCQs
  const mathQuiz = await prisma.quiz.create({
    data: {
      title: "Mathematics MCQs",
      timeLimit: 600, // 10 minutes
      questions: {
        create: [
          {
            text: "What is 15 + 27?",
            options: ["40", "42", "44", "41"],
            correctAnswer: 1,
          },
          {
            text: "What is 9 × 7?",
            options: ["63", "56", "72", "54"],
            correctAnswer: 0,
          },
          {
            text: "What is 144 ÷ 12?",
            options: ["11", "13", "12", "14"],
            correctAnswer: 2,
          },
          {
            text: "What is 25% of 80?",
            options: ["15", "25", "20", "30"],
            correctAnswer: 2,
          },
          {
            text: "What is the square root of 81?",
            options: ["7", "8", "9", "10"],
            correctAnswer: 2,
          },
          {
            text: "What is 3³ (3 raised to the power of 3)?",
            options: ["9", "18", "27", "81"],
            correctAnswer: 2,
          },
          {
            text: "If x + 8 = 15, what is x?",
            options: ["6", "7", "8", "9"],
            correctAnswer: 1,
          },
          {
            text: "What is 0.75 expressed as a fraction?",
            options: ["1/4", "3/4", "2/3", "7/10"],
            correctAnswer: 1,
          },
          {
            text: "What is the area of a rectangle with length 8 and width 5?",
            options: ["30", "35", "40", "45"],
            correctAnswer: 2,
          },
          {
            text: "What is 2.5 × 4?",
            options: ["8", "9", "10", "11"],
            correctAnswer: 2,
          },
        ],
      },
    },
  });

  console.log(`Created Math Quiz (ID: ${mathQuiz.id}) with 10 questions`);

  // Create a second quiz
  const scienceQuiz = await prisma.quiz.create({
    data: {
      title: "General Knowledge",
      timeLimit: 300,
      questions: {
        create: [
          {
            text: "What is the capital of Pakistan?",
            options: ["Lahore", "Karachi", "Islamabad", "Rawalpindi"],
            correctAnswer: 2,
          },
          {
            text: "How many continents are there on Earth?",
            options: ["5", "6", "7", "8"],
            correctAnswer: 2,
          },
          {
            text: "What is the boiling point of water in Celsius?",
            options: ["90°C", "100°C", "110°C", "120°C"],
            correctAnswer: 1,
          },
        ],
      },
    },
  });

  console.log(`Created General Knowledge Quiz (ID: ${scienceQuiz.id}) with 3 questions`);
  console.log("Seed completed successfully!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
