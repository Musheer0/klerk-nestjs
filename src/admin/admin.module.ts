import { Module } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { DbModule } from 'src/db/db.module';

@Module({
  providers: [AdminService],
  controllers: [AdminController],
  imports:[DbModule]
})
export class AdminModule {}
