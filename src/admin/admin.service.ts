import { Injectable } from '@nestjs/common';
import { DbService } from 'src/db/db.service';

@Injectable()
export class AdminService {
    constructor(private db:DbService){};
    

}
